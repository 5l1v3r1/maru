msvc:
	cl /nologo /DTEST /O2 /Os maru.c
	cl /nologo /DTEST /O2 /Os maru2.c  
gnu:	
	gcc -DTEST -O2 -Os maru.c -omaru
	gcc -DTEST -O2 -Os maru2.c -omaru2 
clang:
	clang -DTEST -O2 -Os maru.c -omaru
	clang -DTEST -O2 -Os maru2.c -omaru2	