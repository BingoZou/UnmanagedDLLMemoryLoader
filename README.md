# UnmanagedDLLMemoryLoader 
用C#实现从内存中加载非托管的DLL，支持32位和64位编译，如果需要64位编译请在项目属性中定义条件编译符号_WIN64。

该类参考：https://blog.csdn.net/Vblegend_2013/article/details/82530486 这篇博客实现，修复原有类会导致
程序异常退出的bug，新增64位的支持。

普通的LoadLibrary和LoadLibraryEx函数加载Dll都必须从本地文件加载，使用本类可以直接把非托管Dll嵌入.Net程序集，
然后再从内存中加载Dll。
