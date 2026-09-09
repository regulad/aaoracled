#import "AppDelegate.h"
#import "AttestClient.h"

// Harness base URL, reached on-device via the SSH reverse tunnel:
//   ssh -R 8080:127.0.0.1:8080 thylacine
// Override at build time with -DORACLED_BASE=@"http://127.0.0.1:PORT".
#ifndef ORACLED_BASE
#define ORACLED_BASE @"http://127.0.0.1:8080"
#endif

@interface RootViewController : UIViewController
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) AttestClient *client;
- (void)run;
@end

@implementation RootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(20, 60, 180, 44);
    [btn setTitle:@"Run (reuse key)" forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(run) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];

    UIButton *fbtn = [UIButton buttonWithType:UIButtonTypeSystem];
    fbtn.frame = CGRectMake(200, 60, 160, 44);
    [fbtn setTitle:@"Force NEW key" forState:UIControlStateNormal];
    [fbtn addTarget:self action:@selector(runForce) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:fbtn];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 120, 0, 0)];
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.logView.frame = CGRectMake(10, 120, self.view.bounds.size.width - 20,
                                    self.view.bounds.size.height - 140);
    self.logView.editable = NO;
    self.logView.backgroundColor = UIColor.blackColor;
    self.logView.textColor = UIColor.greenColor;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:11];
    [self.view addSubview:self.logView];

    self.client = [[AttestClient alloc] initWithBaseURL:[NSURL URLWithString:ORACLED_BASE]];
}

- (void)appendLog:(NSString *)line {
    self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", line];
}

- (void)run {
    [self appendLog:@"--- run (reuse key) ---"];
    __weak typeof(self) w = self;
    [self.client runWithLogSink:^(NSString *line) { [w appendLog:line]; } forceNewKey:NO];
}

- (void)runForce {
    [self appendLog:@"--- run (FORCE new key) ---"];
    __weak typeof(self) w = self;
    [self.client runWithLogSink:^(NSString *line) { [w appendLog:line]; } forceNewKey:YES];
}

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    RootViewController *vc = [RootViewController new];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    // Auto-run once on launch so the baseline can be captured headlessly.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [vc run]; });
    return YES;
}

@end
