// Reproducible Mochi vector icon; uses public AppKit APIs without umbrella headers.
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>
#import <Foundation/NSData.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSFileManager.h>
#import <Foundation/NSGeometry.h>
@interface NSBitmapImageRep:NSObject
- (id)initWithBitmapDataPlanes:(unsigned char **)p pixelsWide:(NSInteger)w pixelsHigh:(NSInteger)h bitsPerSample:(NSInteger)b samplesPerPixel:(NSInteger)s hasAlpha:(BOOL)a isPlanar:(BOOL)i colorSpaceName:(NSString *)c bytesPerRow:(NSInteger)r bitsPerPixel:(NSInteger)bits;
- (NSData *)representationUsingType:(NSUInteger)t properties:(NSDictionary *)p;
@end
@interface NSGraphicsContext:NSObject
+ (id)graphicsContextWithBitmapImageRep:(id)b;
+ (void)setCurrentContext:(id)c;
+ (void)saveGraphicsState;
+ (void)restoreGraphicsState;
+ (id)currentContext;
- (void)setCompositingOperation:(NSUInteger)o;
@end
@interface NSColor:NSObject
+ (id)colorWithSRGBRed:(double)r green:(double)g blue:(double)b alpha:(double)a;
- (void)setFill;
- (void)setStroke;
@end
@interface NSBezierPath:NSObject
+ (id)bezierPath;
+ (id)bezierPathWithRoundedRect:(NSRect)r xRadius:(double)x yRadius:(double)y;
+ (id)bezierPathWithOvalInRect:(NSRect)r;
- (void)moveToPoint:(NSPoint)p;
- (void)curveToPoint:(NSPoint)p controlPoint1:(NSPoint)a controlPoint2:(NSPoint)b;
- (void)closePath;
- (void)fill;
- (void)stroke;
- (void)setLineWidth:(double)w;
- (void)setLineCapStyle:(NSUInteger)s;
@end
@interface NSAffineTransform:NSObject
+ (id)transform;
- (void)scaleBy:(double)s;
- (void)concat;
@end
static NSColor *color(double r,double g,double b,double a){return [NSColor colorWithSRGBRed:r green:g blue:b alpha:a];}
static void fill(NSBezierPath *p,NSColor *c){[c setFill];[p fill];}
static void draw(NSString *file,NSInteger size,BOOL mask){
 NSBitmapImageRep *rep=[[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL pixelsWide:size pixelsHigh:size bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES isPlanar:NO colorSpaceName:@"NSDeviceRGBColorSpace" bytesPerRow:0 bitsPerPixel:0];
 [NSGraphicsContext saveGraphicsState];[NSGraphicsContext setCurrentContext:[NSGraphicsContext graphicsContextWithBitmapImageRep:rep]];
 NSAffineTransform *scale=[NSAffineTransform transform];[scale scaleBy:(double)size/1024];[scale concat];
 if(!mask){fill([NSBezierPath bezierPathWithRoundedRect:NSMakeRect(0,0,1024,1024) xRadius:225 yRadius:225],color(.77,.91,.84,1));fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(170,180,684,120)],color(.36,.61,.47,.25));}
 NSBezierPath *body=[NSBezierPath bezierPath];[body moveToPoint:NSMakePoint(170,300)];[body curveToPoint:NSMakePoint(512,780) controlPoint1:NSMakePoint(158,615) controlPoint2:NSMakePoint(310,780)];[body curveToPoint:NSMakePoint(854,300) controlPoint1:NSMakePoint(714,780) controlPoint2:NSMakePoint(866,615)];[body curveToPoint:NSMakePoint(170,300) controlPoint1:NSMakePoint(770,205) controlPoint2:NSMakePoint(254,205)];[body closePath];fill(body,mask?color(0,0,0,1):color(1,.85,.87,1));
 if(mask)[[NSGraphicsContext currentContext] setCompositingOperation:8];
 NSColor *ink=mask?color(0,0,0,1):color(.23,.19,.25,1);
 fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(385,445,36,52)],ink);fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(603,445,36,52)],ink);
 NSBezierPath *smile=[NSBezierPath bezierPath];[smile moveToPoint:NSMakePoint(470,420)];[smile curveToPoint:NSMakePoint(554,420) controlPoint1:NSMakePoint(490,385) controlPoint2:NSMakePoint(534,385)];[ink setStroke];[smile setLineWidth:15];[smile setLineCapStyle:1];[smile stroke];
 if(!mask){fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(300,395,65,33)],color(.96,.56,.64,.7));fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(660,395,65,33)],color(.96,.56,.64,.7));fill([NSBezierPath bezierPathWithOvalInRect:NSMakeRect(330,630,120,35)],color(1,1,1,.55));}
 [NSGraphicsContext restoreGraphicsState];[[rep representationUsingType:4 properties:@{}] writeToFile:file atomically:YES];
}
int main(int argc,char **argv){@autoreleasepool{if(argc!=2)return 1;NSString *folder=[NSString stringWithUTF8String:argv[1]];[[NSFileManager defaultManager] createDirectoryAtPath:folder withIntermediateDirectories:YES attributes:nil error:nil];int sizes[]={16,32,64,128,256,512,1024};for(int i=0;i<7;i++)draw([folder stringByAppendingPathComponent:[NSString stringWithFormat:@"mochi-%d.png",sizes[i]]],sizes[i],NO);draw([folder stringByAppendingPathComponent:@"mochi-status.png"],44,YES);return 0;}}
