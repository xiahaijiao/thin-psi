rm -f psi.so
originFile=`find ./ | grep libPSI_Linux`
ln -s $originFile psi.so
echo -e "aaaaaaa\n10"|java -jar testPSI.jar
