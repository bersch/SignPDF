//
// SignPDF.java
//
// Usage: java SignPDF document.pdf
//
// Copyright: (c) 2012  Bernhard Schneider <bernhard@neaptide.org>
//
// This program is free software: you can use, redistribute, and/or modify
// it under the terms of the GNU Affero General Public License, version 3
// or later ("AGPL"), as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//


//import java.security.spec.*;
//import java.security.cert.*;
import java.io.*;
import java.util.*;
import java.security.*;

/* chmod */
import com.sun.jna.Library;
import com.sun.jna.Native;

//import org.bouncycastle.*;
//import org.bouncycastle.tsp.*;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

// import java.io.FileInputStream;
// import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfSignature;
//import com.itextpdf.text.DocumentException;
//import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;


import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;

import com.itextpdf.text.pdf.*;


public class SignPDF {

	static String version = "1.0";	

	static String path;
	static String src;
	static String dest;
	static String keystore_password;
	static String key_password;
	static String reason;
	static String location;
	static String contact;
	static String alias;
	static String tsa_url;
	static String tsa_login;
	static String tsa_passw;
	static String http_proxy_host;
	static String http_proxy_port;
	static String https_proxy_host;
	static String https_proxy_port;
	static String root_cert;
	static String rcname;
	
	static Properties config = new Properties();
	private static final long TICKS_PER_DAY = 1000 * 60 * 60 * 24;

	
	static char[] readPassword(String msg) throws RuntimeException {
		Console cons = System.console();
		if (cons == null) 
			throw new RuntimeException("can't continue w/o console");
		char[] pwd = cons.readPassword("%s: ", msg );
		return pwd;
	}
	
	public static boolean getProperties() throws FileNotFoundException, IOException {
		try { config.load(new FileInputStream(rcname)); } 
		catch (IOException e) { return false;	}	

		path              = config.getProperty("keystore");
		keystore_password = config.getProperty("keystore_password");
		key_password      = config.getProperty("keystore_key_password");
		alias             = config.getProperty("keystore_key_alias");
		reason            = config.getProperty("reason");
		location          = config.getProperty("location");
		contact           = config.getProperty("contact");
		tsa_url           = config.getProperty("tsa_url");
		tsa_login         = config.getProperty("tsa_login");
		tsa_passw         = config.getProperty("tsa_passw");
		root_cert         = config.getProperty("root_cert");
		http_proxy_host   = config.getProperty("http_proxy_host");
		http_proxy_port   = config.getProperty("http_proxy_port");
		https_proxy_host  = config.getProperty("https_proxy_host");
		https_proxy_port  = config.getProperty("https_proxy_port");
		
		
		if (path.length() == 0) 
			throw new FileNotFoundException("can't continue w/o keystore.");
		
		// read phrase if "", otherwise is null
		if (keystore_password.length() == 0) 
			keystore_password = new String(readPassword("keystore_password"));
		
		// read phrase if "", otherwise is null
		if (key_password.length() == 0) 
			key_password = new String(readPassword("keystore_key_password"));

		// proxies
		boolean use_proxy = false;
		if (http_proxy_host != null && http_proxy_host.length() > 0
				&& http_proxy_port != null && http_proxy_port.length() > 0) {
				use_proxy = true;
		    	System.setProperty("http.proxyHost",http_proxy_host);
		    	System.setProperty("http.proxyPort",http_proxy_port);
			}
		if (https_proxy_host != null && https_proxy_host.length() > 0
				&& https_proxy_port != null && https_proxy_port.length() > 0) {
				use_proxy = true;
		    	System.setProperty("https.proxyHost",https_proxy_host);
		    	System.setProperty("https.proxyPort",https_proxy_port);
		}

		if (use_proxy)
			System.setProperty("java.net.useSystemProxies", "true");

		return true;
	}
	
	interface CLibrary extends Library {
		public int chmod(String path, int mode);
	}
	
	public static void createDefaultProperties() {
		CLibrary libc = (CLibrary) Native.loadLibrary("c", CLibrary.class);	
		
		try {
			FileOutputStream out = new FileOutputStream(rcname);
			
			config.setProperty("keystore","/path/to/keystore");
			config.setProperty("keystore_password", "");
			config.setProperty("keystore_key_password", "");
			config.setProperty("keystore_key_alias", "");
			config.setProperty("reason", "some corp certified");
			config.setProperty("location", "location");
			config.setProperty("contact", "name <name@domain.tld>");
			config.setProperty("tsa_url", "");
			config.setProperty("tsa_login", "");
			config.setProperty("tsa_passw", "");
			config.setProperty("root_cert", "");
			config.setProperty("http_proxy_host","");
			config.setProperty("http_proxy_port","");
			config.setProperty("https_proxy_host","");
			config.setProperty("https_proxy_port","");
			
			config.store(out, " " + rcname);
			libc.chmod(rcname, 0600);
			System.err.println("Configuration file created (" + rcname + "). Please edit it first!");
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
	public static void main(String args[]) {
		try {

		if (args.length != 1) {
			System.err.println("usage: $0 <pdf-file>");
			System.exit(1);
		}
		src = args[0];
		dest = src + ".temp";

		rcname = System.getenv("SIGNPDFRC");
	    if (rcname == null || rcname.length() == 0)
	    	rcname = System.getenv("HOME") + "/.signpdf";	    	
	    else
	    	System.out.println("using SIGNPDFRC=" + rcname);
		
		if (!getProperties()) 
			createDefaultProperties();
				
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(path), keystore_password.toCharArray());
        if (alias == null || alias.length() == 0) 
        	alias = (String)ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        PrivateKey key = (PrivateKey) ks.getKey(alias, key_password.toCharArray());        
        
        X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
        System.out.println("Signer ID serial     " + cert.getSerialNumber());
        System.out.println("Signer ID version    " + cert.getVersion());
        System.out.println("Signer ID issuer     " + cert.getIssuerDN());
        System.out.println("Signer ID not before " + cert.getNotBefore());        
        System.out.println("Signer ID not after  " + cert.getNotAfter());
        
        // show days valid
        long ticks_now  = new Date().getTime();
        long ticks_to   = cert.getNotAfter().getTime();
        
        long ticks_delta = ( ticks_to - ticks_now ) / TICKS_PER_DAY;
        System.out.println("Certificate will expire in " + ticks_delta + " days.");

        Signature s = Signature.getInstance("SHA1withRSA");
        s.initVerify(ks.getCertificate(alias));

        try {
			cert.checkValidity();
			System.out.println("Validation check passed.");
		} catch (Exception e) {
			System.out.println("Certificate expired or invalid. Abroting.");
			System.exit(1);
		}

        
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        //PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, false);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        stamper.setEncryption(true, null, null,
        		PdfWriter.ALLOW_PRINTING | PdfWriter.ALLOW_SCREENREADERS | PdfWriter.ALLOW_COPY);
        
        HashMap<String, String> info = reader.getInfo();
        info.put("Creator", "SingPDF " + version);
        stamper.setMoreInfo(info);
        
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setContact(contact);
        appearance.setCrypto(key, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);

        /// ts + ocsp
    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
    	dic.setReason(appearance.getReason());
    	dic.setLocation(appearance.getLocation());
    	dic.setContact(appearance.getContact());
    	dic.setDate(new PdfDate(appearance.getSignDate()));
    	appearance.setCryptoDictionary(dic);
        
        
        // timestamping + ocsp
        
        if (tsa_url != null && tsa_url.length() > 0) {
        	
        	byte[] ocsp  = null;
        	TSAClient tsc = null;
        
        	int contentEstimated = 15000;
        	HashMap<PdfName,Integer> exc = new HashMap<PdfName, Integer>();
        	exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        	appearance.preClose(exc);
                	
        	InputStream data = appearance.getRangeStream();
        	MessageDigest mdig = MessageDigest.getInstance("SHA1");
        	
        	byte buf[] = new byte[8192];
        	int n;
        	while ((n = data.read(buf)) > 0) {
        		mdig.update(buf, 0, n);
        	}
        	
        	
        	if (root_cert != null && root_cert.length() > 0) {
        		String url = PdfPKCS7.getOCSPURL((X509Certificate)chain[0]);
        		CertificateFactory cf = CertificateFactory.getInstance("X509");
                FileInputStream is = new FileInputStream(root_cert);
                X509Certificate root = (X509Certificate) cf.generateCertificate(is);
                ocsp = new OcspClientBouncyCastle().getEncoded((X509Certificate)chain[0], root, url);
        	}

        	byte hash[]  = mdig.digest();
        	Calendar cal = Calendar.getInstance();
        	PdfPKCS7 sgn = new PdfPKCS7(key, chain, null, "SHA1", null, false);
        	byte sh[]    = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
        	sgn.update(sh, 0, sh.length);
        	
        	if (tsa_url != null && tsa_url.length() > 0) {
        		tsc = new TSAClientBouncyCastle(tsa_url, tsa_login, tsa_passw);
        		byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);
        		if (contentEstimated + 2 < encodedSig.length) 
        			throw new Exception("Not enough space");
        		byte[] paddedSig = new byte[contentEstimated];
        		System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
        		PdfDictionary dic2 = new PdfDictionary();
        		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        		appearance.close(dic2);
        	}
        }
        // ~timestamping + ocsp 
        
        File mysrc = new File(src); mysrc.delete();
        File mydest = new File(dest); mydest.renameTo(mysrc);
        
        System.exit(0);
		}

		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}
