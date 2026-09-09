#import "AttestClient.h"
#import <DeviceCheck/DeviceCheck.h>
#import <CommonCrypto/CommonDigest.h>

static NSString *const kKeyIdDefault = @"oracled.keyId";       // persisted attested keyId
static NSString *const kForceFreshDefault = @"oracled.forceFresh"; // one-shot force flag

@interface AttestClient ()
@property (nonatomic, strong) NSURL *baseURL;
@property (nonatomic, copy) void (^logSink)(NSString *);
@property (nonatomic, strong) DCAppAttestService *service;
@end

@implementation AttestClient

- (instancetype)initWithBaseURL:(NSURL *)baseURL {
    if ((self = [super init])) {
        _baseURL = baseURL;
        _service = DCAppAttestService.sharedService;
    }
    return self;
}

- (void)log:(NSString *)fmt, ... {
    va_list args; va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[oracled] %@", line);
    if (self.logSink) {
        dispatch_async(dispatch_get_main_queue(), ^{ self.logSink(line); });
    }
}

static NSData *sha256(NSData *data) {
    unsigned char h[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, h);
    return [NSData dataWithBytes:h length:CC_SHA256_DIGEST_LENGTH];
}

#pragma mark - HTTP helpers

- (void)getChallenge:(void (^)(NSString *challengeB64, NSError *err))done {
    NSURL *u = [self.baseURL URLByAppendingPathComponent:@"challenge"];
    NSURLSessionDataTask *t =
        [NSURLSession.sharedSession dataTaskWithURL:u
                                  completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e) { done(nil, e); return; }
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        done(j[@"challenge"], nil);
    }];
    [t resume];
}

- (void)postJSON:(NSDictionary *)body to:(NSString *)path
            done:(void (^)(NSDictionary *resp, NSError *err))done {
    NSURL *u = [self.baseURL URLByAppendingPathComponent:path];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSURLSessionDataTask *t =
        [NSURLSession.sharedSession dataTaskWithRequest:req
                                      completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e) { done(nil, e); return; }
        NSDictionary *j = d.length ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : @{};
        done(j, nil);
    }];
    [t resume];
}

#pragma mark - Flow

- (void)runWithLogSink:(void (^)(NSString *))logSink {
    [self runWithLogSink:logSink forceNewKey:NO];
}

- (void)runWithLogSink:(void (^)(NSString *))logSink forceNewKey:(BOOL)force {
    self.logSink = logSink;

    if (!self.service.isSupported) {
        [self log:@"DCAppAttestService NOT supported on this device — abort."];
        return;
    }

    NSUserDefaults *ud = NSUserDefaults.standardUserDefaults;
    // One-shot force flag (settable externally via `defaults write` / Frida).
    if ([ud boolForKey:kForceFreshDefault]) {
        force = YES;
        [ud removeObjectForKey:kForceFreshDefault];
        [self log:@"force-fresh flag set externally"];
    }
    if (force) {
        [ud removeObjectForKey:kKeyIdDefault];
        [self log:@"FORCING new key (persisted keyId cleared)"];
    }

    NSString *stored = [ud stringForKey:kKeyIdDefault];
    if (stored.length) {
        [self log:@"reusing persisted keyId %@... (assertion only, no new attestation)",
            [stored substringToIndex:MIN(16u, (unsigned)stored.length)]];
        [self assertWithKeyId:stored remintOnUnknown:YES];
    } else {
        [self log:@"no persisted key — minting + attesting once."];
        [self mintAttestThenAssert];
    }
}

// Full path: generateKey -> persist -> attestKey -> POST /attest -> assert.
- (void)mintAttestThenAssert {
    [self getChallenge:^(NSString *challengeB64, NSError *err) {
        if (err) { [self log:@"challenge error: %@", err.localizedDescription]; return; }

        [self.service generateKeyWithCompletionHandler:^(NSString *keyId, NSError *kerr) {
            if (kerr) { [self log:@"generateKey error: %@", kerr.localizedDescription]; return; }
            [self log:@"generateKey -> keyId %@...", [keyId substringToIndex:MIN(16u, (unsigned)keyId.length)]];
            // Persist immediately so a crash mid-attest doesn't strand an un-tracked key.
            [NSUserDefaults.standardUserDefaults setObject:keyId forKey:kKeyIdDefault];

            NSData *challenge = [[NSData alloc] initWithBase64EncodedString:challengeB64 options:0];
            [self.service attestKey:keyId clientDataHash:sha256(challenge)
                  completionHandler:^(NSData *attestation, NSError *aerr) {
                if (aerr) { [self log:@"attestKey error: %@", aerr.localizedDescription]; return; }
                [self log:@"attestKey -> %lu bytes. POST /attest...", (unsigned long)attestation.length];

                [self postJSON:@{ @"keyId": keyId,
                                  @"attestation": [attestation base64EncodedStringWithOptions:0],
                                  @"challenge": challengeB64 }
                            to:@"attest"
                          done:^(NSDictionary *resp, NSError *perr) {
                    if (perr) { [self log:@"/attest error: %@", perr.localizedDescription]; return; }
                    [self log:@"/attest -> genuine=%@ app_id=%@",
                        resp[@"ok"], resp[@"observed"][@"app_id"]];
                    [self assertWithKeyId:keyId remintOnUnknown:NO];
                }];
            }];
        }];
    }];
}

- (void)assertWithKeyId:(NSString *)keyId remintOnUnknown:(BOOL)remint {
    [self getChallenge:^(NSString *challengeB64, NSError *err) {
        if (err) { [self log:@"assert challenge error: %@", err.localizedDescription]; return; }
        NSData *challenge = [[NSData alloc] initWithBase64EncodedString:challengeB64 options:0];

        [self.service generateAssertion:keyId clientDataHash:sha256(challenge)
                      completionHandler:^(NSData *assertion, NSError *aerr) {
            if (aerr) { [self log:@"generateAssertion error: %@", aerr.localizedDescription]; return; }
            [self log:@"generateAssertion -> %lu bytes. POST /assert...", (unsigned long)assertion.length];

            [self postJSON:@{ @"keyId": keyId,
                              @"assertion": [assertion base64EncodedStringWithOptions:0],
                              @"challenge": challengeB64 }
                        to:@"assert"
                      done:^(NSDictionary *resp, NSError *perr) {
                if (perr) { [self log:@"/assert error: %@", perr.localizedDescription]; return; }
                // Self-heal: if the harness lost its key store (restart), re-mint once.
                if (remint && (resp[@"error"] || ![resp[@"ok"] boolValue])) {
                    [self log:@"harness doesn't know this key (%@) — re-minting once.",
                        resp[@"error"] ?: @"assert failed"];
                    [NSUserDefaults.standardUserDefaults removeObjectForKey:kKeyIdDefault];
                    [self mintAttestThenAssert];
                    return;
                }
                [self log:@"/assert -> ok=%@ counter=%@",
                    resp[@"ok"], resp[@"observed"][@"counter"]];
                [self log:@"DONE."];
            }];
        }];
    }];
}

@end
