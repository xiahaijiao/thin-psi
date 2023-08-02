# psi

yum install gcc gcc-c++ make java-1.8.0-openjdk -y 




# 连接
- https://github.com/xiahaijiao/psi/blob/main/README.md
- https://github.com/xiahaijiao/thin-psi/blob/main/README.md 

```bash
centos7.9编译失败


/usr/bin/ld: /usr/lib/gcc/x86_64-redhat-linux/4.8.5/crtbeginT.o: relocation R_X86_64_32 against hidden symbol `__TMC_END__' can not be used when making a shared object
/usr/bin/ld: final link failed: Nonrepresentable section on output



cd /usr/lib/gcc/x86_64-redhat-linux/4.8.5/
cp crtbeginT.o crtbeginT.o.bak
cp crtbeginS.o crtbeginT.o



```
