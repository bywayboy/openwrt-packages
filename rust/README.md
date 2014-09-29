RUST language package for OpenWRT
======

在编译这个软件包之前，您首先需要完成如下工作:
*	安装依赖项
*	修改python软件包


###安装依赖项
执行如下命令即可完成安装
···
	apt-get install gyp bzip2-dev
···

###修改python软件包

首先假定您在OpenWRT的目录下, 
*	进入到 package/feeds/packages/python/patches/
*	打开 110-enable-zlib.patch
*	用如下内容覆盖
```
--- 
Modules/Setup.dist | 2 +- 
1 file changed, 1 insertion(+), 1 deletion(-) 

--- a/Modules/Setup.dist 
+++ b/Modules/Setup.dist 
@@ -460,7 +460,9 @@ GLHACK=-Dclear=__GLclear 
# Andrew Kuchling's zlib module. 
# This require zlib 1.1.3 (or later). 
# See http://www.gzip.org/zlib/ 
-#zlib zlibmodule.c -I$(prefix)/include -L$(exec_prefix)/lib -lz 
+zlib zlibmodule.c -lz 
+bz2 bz2module.c -lbz2
+thread threadmodule.c -lpthread

# Interface to the Expat XML parser 
#
```
