// Selective Foundation headers keep this small launcher independent of optional
// SDK umbrella modules. AppKit declarations below use its public Objective-C API.
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSValue.h>
#import <Foundation/NSGeometry.h>
#import <Foundation/NSData.h>
#import <Foundation/NSAppleScript.h>
#import <Foundation/NSTask.h>
#import <Foundation/NSJSONSerialization.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSFileManager.h>
#import <Foundation/NSFileHandle.h>
#import <Foundation/NSURL.h>
#import <Foundation/NSError.h>
#import <Foundation/NSProcessInfo.h>
#import <Foundation/NSTimer.h>
#import <Foundation/NSDate.h>
#import <dispatch/dispatch.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdio.h>

@interface NSApplication : NSObject
+ (instancetype)sharedApplication;
- (void)setDelegate:(id)delegate;
- (void)setActivationPolicy:(NSInteger)policy;
- (void)setMainMenu:(id)menu;
- (void)activateIgnoringOtherApps:(BOOL)flag;
- (void)terminate:(id)sender;
- (void)replyToApplicationShouldTerminate:(BOOL)reply;
- (void)run;
@end
@interface NSMenu : NSObject
- (NSInteger)numberOfItems;
- (id)itemAtIndex:(NSInteger)index;
- (void)addItem:(id)item;
- (id)addItemWithTitle:(NSString *)title action:(SEL)action keyEquivalent:(NSString *)key;
- (void)removeAllItems;
- (void)setDelegate:(id)delegate;
@end
@interface NSMenuItem : NSObject
- (void)setView:(id)view;
- (void)setSubmenu:(id)menu;
- (void)setTarget:(id)target;
- (void)setEnabled:(BOOL)enabled;
- (void)setState:(NSInteger)state;
- (void)setRepresentedObject:(id)object;
- (id)representedObject;
- (NSInteger)state;
+ (id)separatorItem;
@end
@interface NSView : NSObject
- (instancetype)initWithFrame:(NSRect)frame;
- (void)addSubview:(id)view;
@end
@interface NSTextField : NSView
+ (instancetype)labelWithString:(NSString *)string;
- (void)setFrame:(NSRect)frame;
@end
@interface NSSwitch : NSView
- (void)setState:(NSInteger)state;
- (void)setTarget:(id)target;
- (void)setAction:(SEL)action;
- (void)setTag:(NSInteger)tag;
- (NSInteger)tag;
- (void)setEnabled:(BOOL)enabled;
@end
@interface NSStatusBar : NSObject
+ (instancetype)systemStatusBar;
- (id)statusItemWithLength:(double)length;
@end
@interface NSStatusItem : NSObject
- (void)setMenu:(id)menu;
- (id)button;
@end
@interface NSImage : NSObject
- (instancetype)initWithContentsOfFile:(NSString *)file;
- (void)setSize:(NSSize)size;
+ (instancetype)imageWithSystemSymbolName:(NSString *)name accessibilityDescription:(NSString *)description;
- (void)setTemplate:(BOOL)value;
@end
@interface NSObject (StatusButton)
- (void)setImagePosition:(NSUInteger)position;
- (void)setTitle:(NSString *)title;
- (void)setImage:(id)image;
- (void)setToolTip:(NSString *)tip;
@end
@interface NSAlert : NSObject
- (void)setMessageText:(NSString *)text;
- (void)setInformativeText:(NSString *)text;
- (id)addButtonWithTitle:(NSString *)title;
- (NSInteger)runModal;
@end
@interface NSRunningApplication : NSObject
+ (instancetype)runningApplicationWithProcessIdentifier:(pid_t)pid;
- (BOOL)activateWithOptions:(NSUInteger)options;
@end
@interface NSObject (AppleDescriptor)
- (NSString *)stringValue;
@end

static NSString *shellQuote(NSString *value) {
    return [NSString stringWithFormat:@"'%@'",[value stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]];
}
static NSString *appleQuote(NSString *value) {
    value=[value stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    value=[value stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    value=[value stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
    return [NSString stringWithFormat:@"\"%@\"",value];
}
static NSString *authorizationSource(NSArray *args) {
    NSMutableArray *quoted=[NSMutableArray array];for(NSString *arg in args)[quoted addObject:shellQuote(arg)];
    return [NSString stringWithFormat:@"do shell script %@ with administrator privileges with prompt %@",
            appleQuote([quoted componentsJoinedByString:@" "]),appleQuote(@"Enter your Mac administrator password once to start Mochi's VPN service. This is not your VPN password. Keep Mochi running in the menu bar to avoid another request.")];
}
static NSApplication *application;

@interface Launcher : NSObject
@property(strong) NSTask *runner;
@property(copy) NSString *python;
@property(copy) NSString *resources;
@property(copy) NSString *socket;
@property BOOL quitting;
@property BOOL portable;
@property BOOL menuPreview;
@property BOOL menuCheck;
@property NSInteger checkStage;
@property int menuResult;
@property(copy) NSString *uiDirectory;
@property(strong) NSStatusItem *statusItem;
@property(strong) NSMenu *statusMenu;
@property(strong) NSTimer *statusTimer;
- (void)probe;
- (void)authorize;
- (void)startDashboard;
- (void)fail:(NSString *)message;
- (NSDictionary *)runtimeEnvironment;
- (NSArray *)argumentsForScript:(NSString *)script tail:(NSArray *)tail;
- (void)setupStatusItem;
- (void)refreshStatus:(id)sender;
- (void)showDashboard:(id)sender;
- (void)toggleVPN:(NSMenuItem *)sender;
- (void)sendGUI:(NSDictionary *)message;
- (void)checkMenu:(id)sender;
@end

@implementation Launcher
- (void)applicationDidFinishLaunching:(id)notification {
    NSMenu *menu=[NSMenu new];NSMenuItem *item=[NSMenuItem new];[menu addItem:item];
    NSMenu *actions=[NSMenu new];
    [actions addItemWithTitle:@"Quit Mochi" action:@selector(terminate:) keyEquivalent:@"q"];
    [item setSubmenu:actions];[application setMainMenu:menu];
    if(self.menuPreview){
        struct stat info;
        if(lstat([self.uiDirectory fileSystemRepresentation],&info)!=0 || !S_ISDIR(info.st_mode) || info.st_uid!=getuid() || (info.st_mode&0777)!=0700){[application terminate:nil];return;}
        [application setActivationPolicy:1];[self setupStatusItem];
        if(self.menuCheck)[NSTimer scheduledTimerWithTimeInterval:.6 target:self selector:@selector(checkMenu:) userInfo:nil repeats:YES];
        return;
    }
    self.resources=[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"Mochi"];
    NSString *embedded=[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Contents/MacOS/MochiRuntime"];
    self.portable=[[NSFileManager defaultManager] isExecutableFileAtPath:embedded];
    if([[[NSBundle mainBundle] objectForInfoDictionaryKey:@"MochiPortable"] boolValue] && !self.portable){[self fail:@"The packaged runtime is missing or damaged. Reinstall Mochi."];return;}
    [application setActivationPolicy:self.portable?1:0];
    if(self.portable)self.python=embedded;
    else for(NSString *path in @[@"/opt/homebrew/opt/python@3.13/bin/python3.13",@"/usr/local/opt/python@3.13/bin/python3.13"])
        if([[NSFileManager defaultManager] isExecutableFileAtPath:path]) {self.python=path;break;}
    if(!self.python){[self fail:@"Python/Tk is missing. This app currently requires Homebrew python-tk@3.13."];return;}
    char directory[]="/private/tmp/mochi-ui-XXXXXX";
    if(!mkdtemp(directory)){[self fail:@"Could not create the private menu control channel."];return;}
    self.uiDirectory=[NSString stringWithUTF8String:directory];
    [self setupStatusItem];
    dispatch_async(dispatch_get_global_queue(0,0),^{[self probe];});
}
- (void)probe {
    @autoreleasepool {
        NSTask *process=[NSTask new];NSPipe *output=[NSPipe pipe];
        process.executableURL=[NSURL fileURLWithPath:self.python];
        process.arguments=[self argumentsForScript:@"desktop_launch.py" tail:@[@"--probe"]];
        process.environment=[self runtimeEnvironment];
        process.standardOutput=output;process.standardError=[NSFileHandle fileHandleWithNullDevice];
        NSError *error=nil;
        if(![process launchAndReturnError:&error]){dispatch_async(dispatch_get_main_queue(),^{[self fail:@"Could not start the dashboard launcher."];});return;}
        NSData *data=[[output fileHandleForReading] readDataToEndOfFile];[process waitUntilExit];
        NSDictionary *info=[NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if(process.terminationStatus!=0 || ![info isKindOfClass:[NSDictionary class]]){
            dispatch_async(dispatch_get_main_queue(),^{[self fail:@"Dashboard dependencies could not load. Install Homebrew python-tk@3.13 and reopen Mochi."];});return;
        }
        dispatch_async(dispatch_get_main_queue(),^{
            NSNumber *pid=info[@"pid"];
            if(pid){
                NSRunningApplication *existing=[NSRunningApplication runningApplicationWithProcessIdentifier:pid.intValue];
                if(existing){[existing activateWithOptions:3];if(!self.runner)[application terminate:nil];return;}
            }
            if(self.runner)return;
            NSString *socket=info[@"socket"];
            if(socket){self.socket=socket;[self startDashboard];return;}
            [self authorize];
        });
    }
}
- (void)authorize {
    NSString *binary=nil;
    NSArray *paths=self.portable?@[[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Contents/Helpers/openvpn"]]:@[@"/opt/homebrew/sbin/openvpn",@"/usr/local/sbin/openvpn"];
    for(NSString *path in paths)
        if([[NSFileManager defaultManager] isExecutableFileAtPath:path]){binary=path;break;}
    if(!binary){[self fail:@"OpenVPN is missing. Install Homebrew OpenVPN before opening Mochi."];return;}
    NSMutableArray *args=[NSMutableArray array];
    if(self.portable){
        [args addObject:@"/usr/bin/env"];
        NSDictionary *env=[self runtimeEnvironment];
        for(NSString *key in @[@"PYTHONHOME",@"PYTHONNOUSERSITE",@"PYTHONDONTWRITEBYTECODE",@"TCL_LIBRARY",@"TK_LIBRARY",@"SSL_CERT_FILE"])
            [args addObject:[NSString stringWithFormat:@"%@=%@",key,env[key]]];
    }
    [args addObject:self.python];
    [args addObjectsFromArray:[self argumentsForScript:@"desktop_bootstrap.py" tail:@[[NSString stringWithFormat:@"%u",getuid()],[NSString stringWithFormat:@"%d",getpid()],binary]]];
    // The administrator password goes only into the native macOS dialog. It is
    // never returned to this process or written to arguments/configuration.
    NSString *source=authorizationSource(args);
    NSDictionary *error=nil;NSAppleScript *script=[[NSAppleScript alloc] initWithSource:source];
    NSString *result=[(id)[script executeAndReturnError:&error] stringValue];
    if(![result hasPrefix:@"/var/run/mochi-"] || ![result hasSuffix:@"/control.sock"] || [result rangeOfString:@"\n"].location!=NSNotFound){
        if([error[NSAppleScriptErrorNumber] intValue]==-128)[application terminate:nil];
        else [self fail:@"VPN startup was cancelled or failed. Close any older Mochi window and try again."];
        return;
    }
    self.socket=result;[self startDashboard];
}
- (void)startDashboard {
    NSTask *process=[NSTask new];process.executableURL=[NSURL fileURLWithPath:self.python];
    process.arguments=[self argumentsForScript:@"desktop_launch.py" tail:@[self.socket]];
    process.environment=[self runtimeEnvironment];
    process.standardOutput=[NSFileHandle fileHandleWithNullDevice];process.standardError=[NSFileHandle fileHandleWithNullDevice];
    process.terminationHandler=^(NSTask *finished){dispatch_async(dispatch_get_main_queue(),^{
        self.runner=nil;
        if(finished.terminationStatus!=0 && !self.quitting)[self fail:@"The dashboard closed unexpectedly. Open Mochi again to reconnect."];
        else [application terminate:nil];
    });};
    self.runner=process;NSError *error=nil;
    if(![process launchAndReturnError:&error]){self.runner=nil;[self fail:@"Could not open the dashboard."];}
}
- (NSInteger)applicationShouldTerminate:(NSApplication *)sender {
    NSTask *process=self.runner;
    if(process && process.running){
        NSAlert *alert=[NSAlert new];[alert setMessageText:@"Quit Mochi?"];
        [alert setInformativeText:@"This disconnects all VPN connections started by this dashboard."];
        [alert addButtonWithTitle:@"Disconnect and quit"];[alert addButtonWithTitle:@"Cancel"];
        if([alert runModal]!=1000)return 0;
        self.quitting=YES;
        process.terminationHandler=^(NSTask *finished){dispatch_async(dispatch_get_main_queue(),^{[application replyToApplicationShouldTerminate:YES];});};
        [process terminate];return 2;
    }
    return 1;
}
- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    if(self.menuPreview){[self showDashboard:nil];return YES;}
    dispatch_async(dispatch_get_global_queue(0,0),^{[self probe];});return YES;
}
- (void)fail:(NSString *)message {
    NSAlert *alert=[NSAlert new];[alert setMessageText:@"Mochi"];[alert setInformativeText:message];[alert addButtonWithTitle:@"OK"];
    [application activateIgnoringOtherApps:YES];[alert runModal];[application terminate:nil];
}
- (NSDictionary *)runtimeEnvironment {
    NSMutableDictionary *env=[[[NSProcessInfo processInfo] environment] mutableCopy];
    if(self.uiDirectory)env[@"MOCHI_UI_SOCKET"]=[self.uiDirectory stringByAppendingPathComponent:@"control.sock"];
    if(self.portable){
        for(NSString *key in [env allKeys])if([key hasPrefix:@"PYTHON"] || [key hasPrefix:@"DYLD_"] || [key isEqualToString:@"__PYVENV_LAUNCHER__"])[env removeObjectForKey:key];
        NSString *contents=[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Contents"];
        env[@"PYTHONHOME"]=[contents stringByAppendingPathComponent:@"Frameworks/Python.framework/Versions/3.14"];
        env[@"PYTHONNOUSERSITE"]=@"1";env[@"PYTHONDONTWRITEBYTECODE"]=@"1";
        env[@"PYTHONPATH"]=@"";
        env[@"TCL_LIBRARY"]=[contents stringByAppendingPathComponent:@"Resources/Runtime/tcl"];
        env[@"TK_LIBRARY"]=[contents stringByAppendingPathComponent:@"Resources/Runtime/tk"];
        env[@"SSL_CERT_FILE"]=[contents stringByAppendingPathComponent:@"Resources/Runtime/cacert.pem"];
    }
    return env;
}
- (NSArray *)argumentsForScript:(NSString *)script tail:(NSArray *)tail {
    NSMutableArray *args=[NSMutableArray array];
    if(self.portable)[args addObjectsFromArray:@[@"-B",@"-s",@"-S"]];
    [args addObject:[self.resources stringByAppendingPathComponent:script]];[args addObjectsFromArray:tail];return args;
}
- (void)setupStatusItem {
    self.statusItem=[[NSStatusBar systemStatusBar] statusItemWithLength:-1.0];
    NSImage *image=[[NSImage alloc] initWithContentsOfFile:[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"mochi-status.png"]];
    if(!image)image=[NSImage imageWithSystemSymbolName:@"network" accessibilityDescription:@"Mochi connections"];
    if(image){[image setSize:NSMakeSize(22,22)];[image setTemplate:YES];[[self.statusItem button] setImage:image];[[self.statusItem button] setTitle:@" Mochi"];[[self.statusItem button] setImagePosition:2];}
    else [[self.statusItem button] setTitle:@"TD"];
    [[self.statusItem button] setToolTip:@"Mochi"];
    self.statusMenu=[NSMenu new];[self.statusMenu setDelegate:self];[self.statusItem setMenu:self.statusMenu];
    self.statusTimer=[NSTimer scheduledTimerWithTimeInterval:3 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
    [self refreshStatus:nil];
}
- (void)menuWillOpen:(NSMenu *)menu {[self refreshStatus:nil];}
- (void)refreshStatus:(id)sender {
    [self.statusMenu removeAllItems];
    NSString *path=[self.uiDirectory stringByAppendingPathComponent:@"state.json"];
    NSDictionary *attributes=[[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSData *data=[NSData dataWithContentsOfFile:path];
    NSDictionary *state=data.length<=16384?[NSJSONSerialization JSONObjectWithData:data?:[NSData data] options:0 error:nil]:nil;
    NSDate *modified=attributes[NSFileModificationDate];
    BOOL fresh=modified && -[modified timeIntervalSinceNow]<20;
    NSArray *profiles=[state isKindOfClass:[NSDictionary class]]?state[@"profiles"]:nil;
    if(![profiles isKindOfClass:[NSArray class]] || profiles.count>10 || !fresh)profiles=nil;
    NSInteger connected=0;
    for(NSDictionary *row in profiles)if([row isKindOfClass:[NSDictionary class]] && [row[@"state"] isEqual:@"connected"])connected++;
    NSMenuItem *header=[self.statusMenu addItemWithTitle:[NSString stringWithFormat:@"Mochi — %ld connected",(long)connected] action:NULL keyEquivalent:@""];
    [header setEnabled:NO];[self.statusMenu addItem:[NSMenuItem separatorItem]];
    if(!profiles){NSMenuItem *waiting=[self.statusMenu addItemWithTitle:@"Dashboard starting or unavailable…" action:NULL keyEquivalent:@""];[waiting setEnabled:NO];}
    for(NSDictionary *row in profiles){
        if(![row isKindOfClass:[NSDictionary class]] || ![row[@"id"] isKindOfClass:[NSString class]] || ![row[@"name"] isKindOfClass:[NSString class]])continue;
        BOOL on=[row[@"state"] isEqual:@"connected"] || [row[@"state"] isEqual:@"connecting"];
        NSString *title=[NSString stringWithFormat:@"%@ — %@",row[@"name"],on?@"On":@"Off"];
        NSMenuItem *item=[self.statusMenu addItemWithTitle:title action:@selector(toggleVPN:) keyEquivalent:@""];
        [item setTarget:self];[item setState:on?1:0];[item setEnabled:![state[@"busy"] boolValue]];
        [item setRepresentedObject:@{@"op":on?@"disconnect":@"connect",@"id":row[@"id"]}];
        if(!self.menuCheck){
            NSView *view=[[NSView alloc] initWithFrame:NSMakeRect(0,0,290,38)];
            NSTextField *label=[NSTextField labelWithString:row[@"name"]];
            [label setFrame:NSMakeRect(18,9,205,22)];[view addSubview:label];
            NSSwitch *toggle=[[NSSwitch alloc] initWithFrame:NSMakeRect(235,5,45,28)];
            [toggle setState:on?1:0];[toggle setEnabled:![state[@"busy"] boolValue]];
            [toggle setTarget:self];[toggle setAction:@selector(toggleMenuSwitch:)];
            [toggle setTag:[self.statusMenu numberOfItems]-1];[view addSubview:toggle];
            [item setView:view];
        }
    }
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *show=[self.statusMenu addItemWithTitle:@"Open dashboard" action:@selector(showDashboard:) keyEquivalent:@""];[show setTarget:self];
    NSMenuItem *quit=[self.statusMenu addItemWithTitle:@"Quit Mochi…" action:@selector(terminate:) keyEquivalent:@"q"];[quit setTarget:application];
    [[self.statusItem button] setToolTip:[NSString stringWithFormat:@"Mochi — %ld connected",(long)connected]];
}
- (void)showDashboard:(id)sender {[self sendGUI:@{@"op":@"show"}];}
- (void)toggleVPN:(NSMenuItem *)sender {[self sendGUI:[sender representedObject]];}
- (void)toggleMenuSwitch:(NSSwitch *)sender {
    NSMenuItem *item=[self.statusMenu itemAtIndex:[sender tag]];
    if([item representedObject])[self toggleVPN:item];
}
- (void)sendGUI:(NSDictionary *)message {
    NSString *path=[self.uiDirectory stringByAppendingPathComponent:@"control.sock"];
    dispatch_async(dispatch_get_global_queue(0,0),^{
        int fd=socket(AF_UNIX,SOCK_STREAM,0);BOOL ok=NO;
        if(fd>=0){
            struct timeval timeout={2,0};int yes=1;
            setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes));
            struct sockaddr_un address={0};address.sun_family=AF_UNIX;
            const char *name=[path fileSystemRepresentation];
            if(strlen(name)<sizeof(address.sun_path)){
                strcpy(address.sun_path,name);
                if(connect(fd,(struct sockaddr *)&address,sizeof(address))==0){
                    NSMutableData *payload=[[NSJSONSerialization dataWithJSONObject:message options:0 error:nil] mutableCopy];
                    [payload appendBytes:"\n" length:1];
                    if(write(fd,payload.bytes,payload.length)==payload.length){
                        char response[256];ssize_t size=read(fd,response,sizeof(response));
                        if(size>0){NSDictionary *reply=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:response length:size] options:0 error:nil];ok=[reply[@"ok"] boolValue];}
                    }
                }
            }
            close(fd);
        }
        dispatch_async(dispatch_get_main_queue(),^{
            if(!ok){NSAlert *alert=[NSAlert new];[alert setMessageText:@"Mochi"];[alert setInformativeText:@"The dashboard is not ready. Wait for startup or finish its current login, then try again."];[alert addButtonWithTitle:@"OK"];[alert runModal];}
            [self refreshStatus:nil];
        });
    });
}
- (void)applicationWillTerminate:(id)notification {
    [self.statusTimer invalidate];
    if(self.uiDirectory && !self.menuPreview)[[NSFileManager defaultManager] removeItemAtPath:self.uiDirectory error:nil];
}
- (void)checkMenu:(id)sender {
    [self refreshStatus:nil];
    NSMutableArray *actions=[NSMutableArray array];
    for(NSInteger index=0;index<[self.statusMenu numberOfItems];index++){
        NSMenuItem *item=[self.statusMenu itemAtIndex:index];if([item representedObject])[actions addObject:item];
    }
    BOOL valid=self.statusItem && [self.statusItem button] && actions.count==2;
    if(valid){
        NSMenuItem *first=actions[0],*second=actions[1];
        valid=[first state]==1 && [second state]==(self.checkStage==1?1:0);
        if(valid && self.checkStage<2){[self toggleVPN:second];self.checkStage++;return;}
        if(valid){[self showDashboard:nil];puts("Native status item, menu on/off IPC and independent connection state passed");}
    }
    if(!valid){self.menuResult=1;fputs("Native menu integration check failed\n",stderr);}
    [application terminate:nil];
}
@end

int main(int argc,const char **argv){@autoreleasepool {
    if(argc==2 && strcmp(argv[1],"--check")==0){
        NSDictionary *error=nil;
        NSAppleScript *script=[[NSAppleScript alloc] initWithSource:authorizationSource(@[@"/example folder/it's a test",@"501"])];
        if(![script compileAndReturnError:&error])return 1;
        puts("Native authorization script syntax passed; no authentication was requested.");return 0;
    }
    application=[NSApplication sharedApplication];Launcher *launcher=[Launcher new];
    if(argc==3 && (strcmp(argv[1],"--tray-preview")==0 || strcmp(argv[1],"--menu-check")==0)){
        launcher.menuPreview=YES;launcher.menuCheck=strcmp(argv[1],"--menu-check")==0;launcher.uiDirectory=[NSString stringWithUTF8String:argv[2]];
    }
    [application setDelegate:launcher];[application run];
    return launcher.menuResult;
}return 0;}
