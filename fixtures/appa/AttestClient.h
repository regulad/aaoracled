#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Drives the App Attest flow against the RP harness:
///   GET /challenge -> generateKey -> attestKey -> POST /attest
///   GET /challenge -> generateAssertion -> POST /assert
/// Every step is NSLog'd (prefix "[oracled]") so it is visible via idevicesyslog
/// or the Frida console when the M3 oracle attaches.
@interface AttestClient : NSObject

/// baseURL is the harness, reached on-device via the SSH reverse tunnel,
/// e.g. http://127.0.0.1:8080
- (instancetype)initWithBaseURL:(NSURL *)baseURL;

/// Steady-state run: reuse the persisted key (assertion only). Mints + attests
/// exactly once, the first time, then persists the keyId. This mirrors real app
/// behaviour and avoids burning Apple attestations / moving risk_metric on every
/// launch. `logSink` receives progress lines for the on-screen view (may be nil).
- (void)runWithLogSink:(nullable void (^)(NSString *line))logSink;

/// Force a brand-new Secure Enclave key + fresh attestation (clears the
/// persisted keyId first). Use only when a test deliberately needs a new key
/// (e.g. the M3.5 matrix). Also triggered by NSUserDefaults bool
/// "oracled.forceFresh" (one-shot; cleared after use).
- (void)runWithLogSink:(nullable void (^)(NSString *line))logSink forceNewKey:(BOOL)force;

@end

NS_ASSUME_NONNULL_END
