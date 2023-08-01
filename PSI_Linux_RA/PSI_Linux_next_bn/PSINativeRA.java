 package com.rongan;
//package com.ronganchina.jni;
import java.util.*;

public class PSINativeRA {
	static {
//		 
		System.load("/opt/PSI_Linux_RA/x64/gccRelease/libPSI_Linux.so");
	}
	
 	public native static String data2Point(String dataString);

 	public native static String pointBlindWithRA(String pointString,String factorString);

 	public native static String getInverseRA(String rasString); 

 	public native static String sm3Hash(String dataString); 

 	public native static int  getIntersect(String[] clients,String[] servers, String[] intersects ); 

}
