# yuris_chs
pieces的hook dll,把dll名改一下就可以用了  
只hook了两个地方，一个CreateFileA和一个GetGetFileAttributesA。  
字体有问题的话还要hook它的CreateFontIndirectA，不过那个我直接在exe里改了，dll就没写
