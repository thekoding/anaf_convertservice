/*
 This file is part of DUKIntegrator.

 DUKIntegrator is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DUKIntegrator is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with DUKIntegrator.  If not, see <http://www.gnu.org/licenses/>.
 */
package pdf;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import dec.LogTrace;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import ro.certsign.nativeLibWrapper.TokenHandle;
//import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
//import sun.security.pkcs11.wrapper.PKCS11;
//import sun.security.pkcs11.wrapper.PKCS11Constants;
import pdf.CertificateChooser;

public class Sign {
    private boolean _hasCertificare = false;
    private boolean _expired = false;
    private String _algorithm = null;
    private boolean _strictAlgorithm = false;
    private static String newLine = System.getProperty("line.separator");
    private String _pkcs11config = "";
    private String _library = null;
    private boolean _isSlot = false;
    private Certificate[] _chain;
    private PrivateKey _privateKey;
    Provider _etpkcs11 = null;
    CertAlias _certAlias = null;
    private String _configPath = null;
    private String[] _signatureFieldNames = null;
    private int _nrPage;
    private float _x;
    private float _y;
    private float _width;
    private float _height;
    private int _nrPageSig = 0;
    private Rectangle _rectSig = null;
    private static String[] _explicatie = { "numar pagina", "x", "y", "latime", "inaltime" };
    private String _signatureReason = "Depunere declaratie";
    private Class _p11Class = null;
    private Object _p11 = null;
    // pt. dll
    // TokenHandle tHandle = null;

    public Sign(String def, String configPath) {
        _configPath = configPath;
        if (initSignature(def) != null) {
            _signatureFieldNames = null;
        }
    }

    public void setNoCertificate() {
        _hasCertificare = false;
        releaseToken();
    }

    public String signPdf(String pdfFile, String pdfFileSigned, String inputPin, String cfgFile,
            CertificateChooser chooser) {
        String rez = signPdfIntern(pdfFile, pdfFileSigned, inputPin, cfgFile, chooser, null);
        if (rez == null || rez.equals("") == true) {
            return null;
        }
        if (_algorithm.equals("mscapi") || System.getProperty("os.name").toLowerCase().indexOf("win") < 0
                || _strictAlgorithm == true) {
            return rez;
        }
        rez = signPdfIntern(pdfFile, pdfFileSigned, inputPin, cfgFile, chooser, "mscapi");
        return rez;
    }

    private String signPdfIntern(String pdfFile, String pdfFileSigned, String inputPin, String cfgFile,
            CertificateChooser chooser, String algorithm) {
        String rez = null;
        if (_hasCertificare == false) {
            rez = initSignPdf(inputPin, cfgFile, chooser, algorithm);
            if (rez == null) {
                _hasCertificare = true;
            } else {
                return rez;
            }
        }
        // if(_algorithm.equals("dll") == false)
        // {
        if (_algorithm.equals("p12") == false) {
            rez = doSignPdf(pdfFile, pdfFileSigned);
        } else {
            // rez = doSignP12(pdfFile, pdfFileSigned);
        }
        // _etpkcs11.clear();
        return rez;
        // }
        // else
        // {
        // return doSignPdfDll(pdfFile, pdfFileSigned);
        // }
    }

    private String initSignPdf(String inputPin, String cfgFile, CertificateChooser chooser, String algorithm) {
        _pkcs11config = "";
        _algorithm = null;
        _strictAlgorithm = false;
        _library = null;
        _expired = false;
        _isSlot = false;
        BufferedReader cfg = null;
        String line = null;
        try {
            cfg = new BufferedReader(new FileReader(cfgFile));
            do {
                line = cfg.readLine();
                if (line == null) {
                    break;
                }
                line = line.trim();
                if (line.startsWith("#") || line.startsWith(";")) {
                    continue;
                }
                String[] parts = line.split("=", 2);
                if (parts.length != 2) {
                    continue;
                }
                if (parts[0].trim().equals("library")) {
                    _library = parts[1].trim();
                } else if (parts[0].trim().equals("slotListIndex") || parts[0].trim().equals("slot")) {
                    _isSlot = true;
                }
                if (parts[0].trim().equals("algorithm")) {
                    if (parts[1].trim().startsWith("!")) {
                        _algorithm = parts[1].trim().substring(1);
                        _strictAlgorithm = true;
                    } else {
                        _algorithm = parts[1].trim();
                    }
                } else {
                    _pkcs11config += line + newLine;
                }
            } while (true);
        } catch (Throwable ex) {
            return "eroare fisier configurare: " + ex.getMessage();
        } finally {
            if (cfg != null) {
                try {
                    cfg.close();
                } catch (IOException ex) {
                    return "eroare inchidere fisier configurare: " + ex.getMessage();
                }
            }
        }
        if (_library == null) {
            return "fisierul de configurare nu contine atributul 'library'";
        }
        if (_algorithm == null) {
            // alegere mai judicioasa!!!
            if (algorithm != null) {
                _algorithm = algorithm;
            } else {
                _algorithm = "sunpkcs11";
            }
        }
        if (_algorithm.equals("sunpkcs11")) {
            // In mod empiric am constatat ca, pe token-urile care au
            // certificate reinnoite CertSign sub acelasi alias, se selecteaza
            // aleatoriu, cand certificatul valid, cand cel expirat.
            // Incercam sa prindem, facand mai multe incercari,
            // certificatul valid
            String err = null;
            for (int i = 0; i < 10; i++) {
                _expired = false;
                err = initSunpkcs11(inputPin, cfgFile, chooser);
                if (_expired == false) {
                    return err;
                }
                _isSlot = true;
            }
            return err;
        } else if (_algorithm.equals("mscapi")) {
            return initMscapi(inputPin, cfgFile, chooser);
        } else if (_algorithm.equals("p12")) {
            return initP12(inputPin);
        }
        // else if(_algorithm.equals("dll"))
        // {
        // return initDll(inputPin, cfgFile, chooser);
        // }
        return "algoritm semnare necunoscut. Corectati in fisierul " + cfgFile + " valoarea atributului 'algorithm'";
    }

    private String initSunpkcs11(String inputPin, String cfgFile, CertificateChooser chooser) {
        KeyStore.PasswordProtection pin = null;
        X509Certificate cert = null;
        String text = null;
        // compune tagul slot
        if (_isSlot == false) {
            long[] slots = null;
            // CK_SLOT_INFO info = null;
            try {
                // urmatoarele 4 instructiuni, precum si instructiunea mai indepartata
                // --> _etpkcs11 = new sun.security.pkcs11.SunPKCS11(configStream);
                // au fost executate folosind java reflection, pt. a putea folosi
                // codul si cu java 64 biti (care nu are pachetul pkcs11)
                // CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
                Class initArgsClass = Class.forName("sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS");
                Object initArgs = initArgsClass.getConstructor().newInstance();
                // initArgs.flags = PKCS11Constants.CKF_OS_LOCKING_OK;
                Field fld = initArgsClass.getDeclaredField("flags");
                fld.setLong(initArgs, Class.forName("sun.security.pkcs11.wrapper.PKCS11Constants")
                        .getField("CKF_OS_LOCKING_OK").getLong(null));
                // PKCS11 p11 = PKCS11.getInstance(_library, "C_GetFunctionList", initArgs,
                // false);
                _p11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
                Method mth = _p11Class.getMethod("getInstance", String.class, String.class, initArgsClass,
                        boolean.class);
                _p11 = mth.invoke(null, _library, "C_GetFunctionList", initArgs, false);
                // slots = p11.C_GetSlotList(true);
                mth = _p11Class.getMethod("C_GetSlotList", boolean.class);
                slots = (long[]) mth.invoke(_p11, true);
                // info = p11.C_GetSlotInfo(slots[0]);
                if (slots != null && slots.length > 0) {
                    // _pkcs11config += "slotListIndex=" + slots[0] + newLine;
                    _pkcs11config += "slot=" + slots[0] + newLine;
                }
            } catch (Throwable t) {
                return "eroare acces driver: " + _library
                        + " (Corectati parametrul library din fisierul dist\\config\\SMART_CARD.cfg astfel incat sa indice calea reala pe calculatorul dumneavoastra catre driverul corespunzator SMART_CARD-ului folosit)"
                        + newLine + "       (" + t + ")";
            }
        }
        try {
            // connect to eToken PKCS#11 provider
            byte[] pkcs11configBytes = _pkcs11config.getBytes();
            ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11configBytes);
            // blocaj cu driverul aladdin 2013-06-06:
            // _etpkcs11 = new sun.security.pkcs11.SunPKCS11(configStream);
            Constructor ct = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
            _etpkcs11 = (Provider) ct.newInstance(configStream);
            Security.addProvider(_etpkcs11);
            // get user PIN
            pin = new KeyStore.PasswordProtection(inputPin.toCharArray());
            // create key store builder
            KeyStore.Builder keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11", _etpkcs11, pin);
            // create key store
            // blocaj cu driverul aladdin 2013-06-06:
            KeyStore keyStore = keyStoreBuilder.getKeyStore();
            String alias = null;
            String error = "certificatul nu a putut fi detectat";
            int cnt = 0, flag = 0;
            Enumeration e = keyStore.aliases();
            List coll = new ArrayList();
            do {
                cnt++;
                alias = String.valueOf(e.nextElement());
                if (keyStore.isKeyEntry(alias) == true) {
                    cert = (X509Certificate) keyStore.getCertificate(alias);
                    try {
                        cert.checkValidity();
                        coll.add(new CertAlias(alias, cert));
                        // break;
                    } catch (CertificateExpiredException ex) {
                        error = "Certificat expirat: " + ex.toString();
                        _expired = true;
                        flag |= 1;
                    } catch (CertificateNotYetValidException ex) {
                        error = "Certificat nu este inca valid: " + ex.toString();
                        flag |= 2;
                    } catch (Throwable ex) {
                        error = "Certificat eronat: " + ex.toString();
                        logError(30, ex);
                        flag |= 4;
                    }
                    // StringBuffer bf = new StringBuffer();
                    // bf.append(chooser._newLine + "Alias
                    // certificat:----------------------------------------------------" +
                    // chooser._newLine);
                    // bf.append(alias);
                    // bf.append(chooser._newLine +
                    // "Certificat----------------------------------------------------" +
                    // chooser._newLine);
                    // bf.append(cert);
                    // bf.append(chooser._newLine + "Private key:
                    // ----------------------------------------------------" + chooser._newLine);
                    // bf.append(keyStore.getKey(alias, null));
                    // bf.append(chooser._newLine + "Sfarsit
                    // certificat----------------------------------------------------" +
                    // chooser._newLine);
                    // chooser.insertMessage(bf.toString());
                }
            } while (e.hasMoreElements());
            if (coll.size() > 1) {
                _certAlias = chooser.chooseCertificate(coll);
            } else if (coll.size() == 0) {
                if (cnt > 1 && flag != 1 && flag != 2 && flag != 4) {
                    error = "Certificatele sunt sau expirate sau nu sunt inca valide sau eronate";
                }
                return error;
            } else {
                _certAlias = (CertAlias) coll.get(0);
            }
            cert = _certAlias._cert;
            alias = _certAlias._alias;
            _expired = false;
            _privateKey = (PrivateKey) keyStore.getKey(alias, null);
            _chain = null;
            _chain = keyStore.getCertificateChain(alias);
            _chain[0] = cert;
        } catch (ProviderException ex) {
            logError(1, ex);
            if (ex.getMessage().equals("Initialization failed")) {
                // return ex.toString() + " (Probabil aveti un alt tip de SmartCard conectat.
                // Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea
                // \"*autoDetect\")";
                return analizaEroare(ex)
                        + " (Probabil aveti un alt tip de SmartCard conectat. Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea \"*autoDetect\")";
            } else if (ex.getMessage().equals("Error parsing configuration")) {
                // return ex.toString() + " (Calea catre driverul SmartCardului (care se afla
                // inscrisa in fisierul .cfg corespunzator acestuia) contine unul din
                // urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder
                // in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si
                // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
                return analizaEroare(ex)
                        + " (Calea catre driverul SmartCardului (care se afla inscrisa in fisierul .cfg corespunzator acestuia) contine unul din urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
            }
            // return ex.toString();
            return analizaEroare(ex);
        } catch (KeyStoreException ex) {
            logError(2, ex);
            if (ex.getMessage().equals("KeyStore instantiation failed")) {
                // return ex.toString() + " (Probabil nu aveti nici un SmartCard conectat sau
                // PIN-ul nu este corect sau PIN blocat datorita depasirii numarului de login
                // esuate sau, daca SmartCardul este Schlumberger, introduceti doar primele 8
                // caractere ale PIN-ului)";
                return analizaEroare(ex)
                        + " (Probabil nu aveti nici un SmartCard conectat sau PIN-ul nu este corect sau PIN blocat datorita depasirii numarului de login esuate sau, daca SmartCardul este Schlumberger, introduceti doar primele 8 caractere ale PIN-ului)";
            }
            return ex.toString();
        } catch (NoSuchAlgorithmException ex) {
            logError(3, ex);
            return ex.toString();
        } catch (UnrecoverableKeyException ex) {
            logError(4, ex);
            return ex.toString();
        } catch (Throwable ex) {
            logError(5, ex);
            return ex.toString();
        }
        return null;
    }

    private String analizaEroare(Throwable ex) {
        String text = ex.toString();
        do {
            try {
                ex = ex.getCause();
                if (ex == null) {
                    return text;
                }
                text = ex.toString();
            } catch (Throwable ex1) {
                return text;
            }
        } while (true);
    }

    private String initMscapi(String inputPin, String cfgFile, CertificateChooser chooser) {
        X509Certificate cert = null;
        // compune tagul slot
        try {
            // add provider
            _etpkcs11 = (Provider) Class.forName("sun.security.mscapi.SunMSCAPI").newInstance();
            // _etpkcs11 = new sun.security.mscapi.SunMSCAPI();
            Security.addProvider(_etpkcs11);
            // create key store
            KeyStore keyStore = KeyStore.getInstance("Windows-MY");
            keyStore.load(null, inputPin.toCharArray());
            fixAliases(keyStore);
            String alias = null;
            String error = "certificatul nu a putut fi detectat";
            int cnt = 0, flag = 0;
            Enumeration e = keyStore.aliases();
            List coll = new ArrayList();
            do {
                cnt++;
                alias = String.valueOf(e.nextElement());
                if (keyStore.isKeyEntry(alias) == true) {
                    cert = (X509Certificate) keyStore.getCertificate(alias);
                    try {
                        cert.checkValidity();
                        coll.add(new CertAlias(alias, cert));
                        // break;
                    } catch (CertificateExpiredException ex) {
                        error = "Certificat expirat: " + ex.toString();
                        _expired = true;
                        flag |= 1;
                    } catch (CertificateNotYetValidException ex) {
                        error = "Certificat nu este inca valid: " + ex.toString();
                        flag |= 2;
                    } catch (Throwable ex) {
                        error = "Certificat eronat: " + ex.toString();
                        logError(30, ex);
                        flag |= 4;
                    }
                    // StringBuffer bf = new StringBuffer();
                    // bf.append(chooser._newLine + "Alias
                    // certificat:----------------------------------------------------" +
                    // chooser._newLine);
                    // bf.append(alias);
                    // bf.append(chooser._newLine +
                    // "Certificat----------------------------------------------------" +
                    // chooser._newLine);
                    // bf.append(cert);
                    // bf.append(chooser._newLine + "Private key:
                    // ----------------------------------------------------" + chooser._newLine);
                    // bf.append(keyStore.getKey(alias, null));
                    // bf.append(chooser._newLine + "Sfarsit
                    // certificat----------------------------------------------------" +
                    // chooser._newLine);
                    // chooser.insertMessage(bf.toString());
                }
            } while (e.hasMoreElements());
            if (coll.size() > 1) {
                _certAlias = chooser.chooseCertificate(coll);
            } else if (coll.size() == 0) {
                if (cnt > 1 && flag != 1 && flag != 2 && flag != 4) {
                    error = "Certificatele sunt sau expirate sau nu sunt inca valide sau eronate";
                }
                return error;
            } else {
                _certAlias = (CertAlias) coll.get(0);
            }
            cert = _certAlias._cert;
            alias = _certAlias._alias;
            _expired = false;

            _privateKey = (PrivateKey) keyStore.getKey(alias, inputPin.toCharArray());
            _chain = null;
            _chain = keyStore.getCertificateChain(alias);
            _chain[0] = cert;
        } catch (ProviderException ex) {
            logError(10, ex);
            if (ex.getMessage().equals("Initialization failed")) {
                return ex.toString()
                        + " (Probabil aveti un alt tip de SmartCard conectat. Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea \"*autoDetect\")";
            } else if (ex.getMessage().equals("Error parsing configuration")) {
                return ex.toString()
                        + " (Calea catre driverul SmartCardului (care se afla inscrisa in fisierul .cfg corespunzator acestuia) contine unul din urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
            }
            return ex.toString();
        } catch (KeyStoreException ex) {
            logError(11, ex);
            if (ex.getMessage().equals("KeyStore instantiation failed")) {
                return ex.toString()
                        + " (Probabil nu aveti nici un SmartCard conectat sau PIN-ul nu este corect sau, daca SmartCardul este Schlumberger, introduceti doar primele 8 caractere ale PIN-ului)";
            }
            return ex.toString();
        } catch (NoSuchAlgorithmException ex) {
            logError(12, ex);
            return ex.toString();
        } catch (UnrecoverableKeyException ex) {
            logError(13, ex);
            return ex.toString();
        } catch (Throwable ex) {
            logError(14, ex);
            return ex.toString();
        }
        return null;
    }

    // workaround pt. cazul certificatelor reinnoite cu acelasi alias (cu cel
    // precedent)
    // modifica aliasurile in obiectul keyStore pt. a le face unice
    private static void fixAliases(KeyStore keyStore) {
        Field field;
        KeyStoreSpi keyStoreVeritable;

        try {
            field = keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

            if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
                Collection entries;
                String alias, hashCode;
                X509Certificate[] certificates;

                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);
                entries = (Collection) field.get(keyStoreVeritable);
                // eroare semnalata pe 2018-03-27: inofensiva, dar suparatoare
                // in adevar Map nu pare sa fie subInterface a lui Collection
                // de testat
                // ? modul Sign; eroare=20: java.lang.ClassCastException: java.util.HashMap
                // cannot be cast to java.util.Collection
                // pdf.Sign.fixAliases(Sign.java:624)
                // pdf.Sign.initMscapi(Sign.java:490)
                // pdf.Sign.initSignPdf(Sign.java:268)
                // pdf.Sign.signPdfIntern(Sign.java:125)
                // pdf.Sign.signPdf(Sign.java:116)
                // general.Integrator.signPdf(Integrator.java:1022)
                // ui.DUKFrame.pdfSigning(DUKFrame.java:978)
                // ui.DUKFrame.run(DUKFrame.java:1130)
                // java.lang.Thread.run(Unknown Source)
                // ? eroare in functia fixAliases(): java.lang.ClassCastException:
                // java.util.HashMap cannot be cast to java.util.Collection entries =
                // (Collection) field.get(keyStoreVeritable);

                for (Object entry : entries) {
                    field = entry.getClass().getDeclaredField("certChain");
                    field.setAccessible(true);
                    certificates = (X509Certificate[]) field.get(entry);

                    hashCode = Integer.toString(certificates[0].hashCode());

                    field = entry.getClass().getDeclaredField("alias");
                    field.setAccessible(true);
                    alias = (String) field.get(entry);

                    if (!alias.equals(hashCode)) {
                        field.set(entry, alias.concat(" - ").concat(hashCode));
                    } // if
                } // for
            } // if
        } catch (Exception exception) {
            logError(20, exception);
            LogTrace.log("eroare in functia fixAliases(): " + exception.toString(), 2);
        }
    }

    // private String initDll(String inputPin, String cfgFile, CertificateChooser
    // chooser)
    // {
    // KeyStore.PasswordProtection pin = null;
    // X509Certificate cert = null;
    // int[] slots;
    // //compune tagul slot
    // try
    // {
    // tHandle = new TokenHandle(_library);
    // slots = tHandle.getSlots();
    // if(slots != null && slots.length > 0)
    // {
    // _pkcs11config += "slot=" + slots[0] + newLine;
    // }
    // else
    // {
    // return "eroare token: niciun slot disponibil";
    // }
    // }
    // catch(Throwable t)
    // {
    // return "eroare acces driver: " + _library + " (Corectati parametrul library
    // din fisierul dist\\config\\SMART_CARD.cfg astfel incat sa indice calea reala
    // pe calculatorul dumneavoastra catre driverul corespunzator SMART_CARD-ului
    // folosit)" + newLine + " (" + t + ")";
    // }
    // try
    // {
    // // connect to eToken PKCS#11 provider
    // byte[] pkcs11configBytes = _pkcs11config.getBytes();
    // ByteArrayInputStream configStream = new
    // ByteArrayInputStream(pkcs11configBytes);
    // _etpkcs11 = new sun.security.pkcs11.SunPKCS11(configStream);
    // Security.addProvider(_etpkcs11);
    // // get user PIN
    // pin = new KeyStore.PasswordProtection(inputPin.toCharArray());
    // // create key store builder
    // KeyStore.Builder keyStoreBuilder = KeyStore.Builder.newInstance("PKCS11",
    // _etpkcs11, pin);
    // // create key store
    // KeyStore keyStore = keyStoreBuilder.getKeyStore();
    // String alias = null;
    // String error = "certificat eronat";
    // int cnt = 0, flag = 0;
    // Enumeration e = keyStore.aliases();
    // List coll = new ArrayList();
    // tHandle.openSession(slots[0]);
    // tHandle.loginToTokenSession(inputPin);
    // byte[] publicKeyContent = null;
    // do
    // {
    // cnt++;
    // alias = String.valueOf(e.nextElement());
    // if(keyStore.isKeyEntry(alias) == true)
    // {
    // cert = (X509Certificate)keyStore.getCertificate(alias);
    // publicKeyContent = cert.getPublicKey().getEncoded();
    // Certificate[] certificates =
    // tHandle.getCertificatesByPublicKey(publicKeyContent);
    // for(int i = 0; i < certificates.length; i++)
    // {
    // cert = (X509Certificate)certificates[i];
    // try
    // {
    // cert.checkValidity();
    // coll.add(new CertAlias(alias, cert));
    // }
    // catch(CertificateExpiredException ex)
    // {
    // error = "Certificat expirat: " + ex.toString();
    // _expired = true;
    // flag |= 1;
    // }
    // catch(CertificateNotYetValidException ex)
    // {
    // error = "Certificat nu este inca valid: " + ex.toString();
    // flag |= 2;
    // }
    // catch(Throwable ex)
    // {
    // error = "Certificat eronat: " + ex.toString();
    // flag |= 4;
    // }
    // }
    // }
    // }
    // while(e.hasMoreElements());
    // if(coll.size() > 1)
    // {
    // _certAlias = chooser.chooseCertificate(coll);
    // }
    // else if(coll.size() == 0)
    // {
    // if(cnt > 1 && flag != 1 && flag != 2 && flag != 4)
    // {
    // error = "Certificatele sunt sau expirate sau nu sunt inca valide sau
    // eronate";
    // }
    // return error;
    // }
    // else
    // {
    // _certAlias = (CertAlias)coll.get(0);
    // }
    // cert = _certAlias._cert;
    // alias = _certAlias._alias;
    // _expired = false;
    // _privateKey = (PrivateKey)keyStore.getKey(alias, null);
    // _chain = null;
    // _chain = keyStore.getCertificateChain(alias);
    // _chain[0] = cert;
    // }
    // catch(ProviderException ex)
    // {
    // if(ex.getMessage().equals("Initialization failed"))
    // {
    // return ex.toString() + " (Probabil aveti un alt tip de SmartCard conectat.
    // Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea
    // \"*autoDetect\")";
    // }
    // else if(ex.getMessage().equals("Error parsing configuration"))
    // {
    // return ex.toString() + " (Calea catre driverul SmartCardului (care se afla
    // inscrisa in fisierul .cfg corespunzator acestuia) contine unul din
    // urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder
    // in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si
    // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
    // }
    // return ex.toString();
    // }
    // catch(KeyStoreException ex)
    // {
    // if(ex.getMessage().equals("KeyStore instantiation failed"))
    // {
    // return ex.toString() + " (Probabil nu aveti nici un SmartCard conectat sau
    // PIN-ul nu este corect sau, daca SmartCardul este Schlumberger, introduceti
    // doar primele 8 caractere ale PIN-ului)";
    // }
    // return ex.toString();
    // }
    // catch(NoSuchAlgorithmException ex)
    // {
    // return ex.toString();
    // }
    // catch(UnrecoverableKeyException ex)
    // {
    // return ex.toString();
    // }
    // catch(Throwable ex)
    // {
    // return ex.toString();
    // }
    // return null;
    // }
    private String doSignPdf(String pdfFile, String pdfFileSigned) {
        try {
            PdfReader reader = new PdfReader(pdfFile);
            FileOutputStream fout = new FileOutputStream(pdfFileSigned);
            PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', new File(pdfFileSigned + ".tmp"));
            PdfSignatureAppearance sap = stp.getSignatureAppearance();
            sap.setCrypto(null, _chain, null, PdfSignatureAppearance.SELF_SIGNED);
            sap.setReason(_signatureReason);
            // sap.setVisibleSignature(new Rectangle(500, 775, 600, 675), 1, null);
            setSignature(reader);
            sap.setVisibleSignature(_rectSig, _nrPageSig, null);
            sap.setExternalDigest(
                    new byte[((RSAPublicKey) _certAlias._cert.getPublicKey()).getModulus().bitLength() / 8], null,
                    "RSA");
            sap.preClose();
            byte[] content = streamToByteArray(sap.getRangeStream());
            Signature signature = Signature.getInstance("SHA1withRSA", _etpkcs11);
            signature.initSign((PrivateKey) _privateKey);
            signature.update(content);
            byte[] signatureBytes = signature.sign();
            // Self-Sign mode
            PdfPKCS7 sig = sap.getSigStandard().getSigner();
            sig.setExternalDigest(signatureBytes, null, "RSA");
            PdfDictionary dic = new PdfDictionary();
            dic.put(PdfName.CONTENTS, new PdfString(sig.getEncodedPKCS1()).setHexWriting(true));
            sap.close(dic);
            new File(pdfFileSigned + ".tmp").delete();

        } catch (FileNotFoundException ex) {
            return ex.toString();
        } catch (ProviderException ex) {
            if (ex.getMessage().equals("Initialization failed")) {
                return ex.toString()
                        + " (Probabil aveti un alt tip de SmartCard conectat. Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea \"*autoDetect\")";
            } else if (ex.getMessage().equals("Error parsing configuration")) {
                return ex.toString()
                        + " (Calea catre driverul SmartCardului (care se afla inscrisa in fisierul .cfg corespunzator acestuia) contine unul din urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
            }
            return ex.toString();
        } catch (NoSuchAlgorithmException ex) {
            return ex.toString();
        } catch (IOException ex) {
            return ex.toString();
        } catch (DocumentException ex) {
            return ex.toString();
        } catch (InvalidKeyException ex) {
            return ex.toString();
        } catch (SignatureException ex) {
            return ex.toString();
        } catch (Throwable ex) {
            return ex.toString();
        } finally {
            // wwww: eliminare key pt a putea introduce un nou pin
            // String str = pin.getPassword().toString();
            // pin.destroy();
            // Security.removeProvider(_etpkcs11.getName());//"SunPKCS11-SmartCard");
            // wwww
        }
        return "";
    }

    // private String doSignPdfDll(String pdfFile, String pdfFileSigned)
    // {
    // try
    // {
    // PdfReader reader = new PdfReader(pdfFile);
    // FileOutputStream fout = new FileOutputStream(pdfFileSigned);
    // PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0');
    // PdfSignatureAppearance sap = stp.getSignatureAppearance();
    // sap.setCrypto(null, _chain, null, PdfSignatureAppearance.SELF_SIGNED);
    // sap.setReason("Declaratie unica");
    // sap.setVisibleSignature(new Rectangle(500, 775, 600, 675), 1, null);
    // sap.setExternalDigest(new
    // byte[((RSAPublicKey)_certAlias._cert.getPublicKey()).getModulus().bitLength()
    // / 8], null, "RSA");
    // sap.preClose();
    // byte[] content = streamToByteArray(sap.getRangeStream());
    // byte[] signatureBytes = tHandle.sign(content,
    // _certAlias._cert.getPublicKey().getEncoded());
    // // Self-Sign mode
    // PdfPKCS7 sig = sap.getSigStandard().getSigner();
    // sig.setExternalDigest(signatureBytes, null, "RSA");
    // PdfDictionary dic = new PdfDictionary();
    // dic.put(PdfName.CONTENTS, new
    // PdfString(sig.getEncodedPKCS1()).setHexWriting(true));
    // sap.close(dic);
    // }
    // catch(FileNotFoundException ex)
    // {
    // return ex.toString();
    // }
    // catch(ProviderException ex)
    // {
    // if(ex.getMessage().equals("Initialization failed"))
    // {
    // return ex.toString() + " (Probabil aveti un alt tip de SmartCard conectat.
    // Deconectati alte tipuri de SmartCarduri (daca exista) si folositi optiunea
    // \"*autoDetect\")";
    // }
    // else if(ex.getMessage().equals("Error parsing configuration"))
    // {
    // return ex.toString() + " (Calea catre driverul SmartCardului (care se afla
    // inscrisa in fisierul .cfg corespunzator acestuia) contine unul din
    // urmatoarele caractere: \"~()\". Solutie: Copiati continutul intregului folder
    // in alta locatie si modificati corespunzator calea din fisierul .cfg. (vezi si
    // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6581254))";
    // }
    // return ex.toString();
    // }
    // catch(IOException ex)
    // {
    // return ex.toString();
    // }
    // catch(DocumentException ex)
    // {
    // return ex.toString();
    // }
    // catch(Throwable ex)
    // {
    // return ex.toString();
    // }
    // finally
    // {
    // //wwww: eliminare key pt a putea introduce un nou pin
    //// String str = pin.getPassword().toString();
    //// pin.destroy();
    //// Security.removeProvider(_etpkcs11.getName());//"SunPKCS11-SmartCard");
    // //wwww
    // }
    // return "";
    // }
    private byte[] streamToByteArray(InputStream is) throws IOException {

        byte[] buff = new byte[512];
        int read = -1;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while ((read = is.read(buff)) >= 0) {

            bos.write(buff, 0, read);
        }
        bos.close();
        return bos.toByteArray();
    }

    public void releaseToken() {
        try {
            for (Provider p : Security.getProviders()) {
                if (p.getName().contains("SunPKCS11")) {
                    Security.removeProvider(p.getName());
                }
            }
            if (_p11Class != null && _p11 != null) {
                Method mth = _p11Class.getMethod("finalize", null);
                mth.invoke(_p11);
            }
            _p11Class = null;
            _p11 = null;
            Thread.sleep(1000);
        } catch (Throwable ex) {
        }
    }

    public String initSignature(String def) {
        String text = null;
        _x = 0;
        _y = 0;
        _width = 150;
        _height = 50;
        if (def == null || def.trim().equals("")) {
            _signatureFieldNames = new String[0];
            return null;
        }
        String[] parts = def.split("\\|", 6);
        if (parts.length != 1 && parts.length != 2 && parts.length != 6) {
            return "definitie certificat '" + def + "' incorecta: se asteapta 1, 2 sau 6 parametri separati prin '|'";
        }
        // extrage nume TextField semnatura
        text = parts[0].trim();
        int ind = 0;
        try {
            _nrPage = 1;
            // extrage numar pagina
            if (parts.length >= 2) {
                _nrPage = Integer.parseInt(parts[1]);
                if (_nrPage == 0) {
                    _nrPage = 1;
                }
                ind++;
                // extrage origine si dimensiuni Rectangle pt. semnatura
                if (parts.length > 2) {
                    _x = Float.parseFloat(parts[2]);
                    ind++;
                    _y = Float.parseFloat(parts[3]);
                    ind++;
                    _width = Float.parseFloat(parts[4]);
                    ind++;
                    _height = Float.parseFloat(parts[5]);
                    if (_width < 0) {
                        _width = 150;
                    }
                    if (_height < 0) {
                        _height = 50;
                    }
                }
            }
        } catch (Throwable ex) {
            return "definitie certificat '" + def + "' incorecta: eroare " + _explicatie[ind] + ": " + ex.toString();
        }
        text = parts[0].trim();
        _signatureFieldNames = text.split("&");
        for (int i = 0; i < _signatureFieldNames.length; i++) {
            text = _signatureFieldNames[i].trim();
            if (text.equals("")) {
                text = "signature";
            }
            _signatureFieldNames[i] = text;
        }
        return null;
    }

    private String initP12(String inputPin) {
        KeyStore ks = null;
        String alias = null;
        try {
            // citire certificat
            ks = KeyStore.getInstance("pkcs12");
            _library = new File(new File(_configPath).getCanonicalPath(), _library).getCanonicalPath();
            ks.load(new FileInputStream(_library), inputPin.toCharArray());
            alias = (String) ks.aliases().nextElement();
            _privateKey = (PrivateKey) ks.getKey(alias, inputPin.toCharArray());
            _chain = ks.getCertificateChain(alias);
        } catch (Throwable e) {
            return "eroare semnare cu certificat '" + _library + "': " + e.toString();
        }
        return null;
    }

    private String setSignature(PdfReader pdfReader) {
        float x0 = 0;
        float y0 = 0;
        float x = 0;
        float y = 0;
        String signatureFieldName = null;
        // incearca determinare camp semnatura
        if (_signatureFieldNames != null) {
            AcroFields.Item item = null;
            for (int i = 0; i < _signatureFieldNames.length; i++) {
                try {
                    item = pdfReader.getAcroFields().getFieldItem(_signatureFieldNames[i]);
                    // Item item1 = _pdfReader.getAcroForm().get(new PDFName());
                    if (item != null) {
                        _nrPageSig = item.getPage(0);
                        PdfArray rectArray = item.getWidget(0).getAsArray(PdfName.RECT);
                        x0 = Float.parseFloat(rectArray.getAsNumber(0).toString());
                        y0 = Float.parseFloat(rectArray.getAsNumber(1).toString());
                        x = Float.parseFloat(rectArray.getAsNumber(2).toString());
                        y = Float.parseFloat(rectArray.getAsNumber(3).toString());
                        _rectSig = new Rectangle(x0, y0, x, y);
                        signatureFieldName = _signatureFieldNames[i];
                        break;
                    }
                } catch (Throwable ex) {
                }
            }
        }
        if (signatureFieldName == null && _signatureFieldNames != null && _signatureFieldNames.length > 0) {
            // TextField necunoscut
            _nrPageSig = pdfReader.getNumberOfPages();
            if (_nrPage < 0) {
                _nrPageSig = Math.max(_nrPageSig + _nrPage + 1, 1);
            } else {
                _nrPageSig = Math.min(_nrPageSig, _nrPage);
            }
            _rectSig = pdfReader.getPageSize(_nrPageSig);
            if (_x < 0) {
                x0 = Math.max(_rectSig.getRight() + _x, _rectSig.getLeft());
                x = Math.min(x0 + _width, _rectSig.getRight());
            } else {
                x0 = Math.min(_x, _rectSig.getRight());
                x = Math.min(x0 + _width, _rectSig.getRight());
            }
            if (_y < 0) {
                y0 = Math.max(_rectSig.getTop() + _y, _rectSig.getBottom());
                y = Math.min(y0 + _height, _rectSig.getTop());
            } else {
                y0 = Math.min(_y, _rectSig.getTop());
                y = Math.min(y0 + _height, _rectSig.getTop());
            }
            _rectSig = new Rectangle(x0, y0, x, y);
            signatureFieldName = "___signature___";
        }
        // else if(_signatureFieldNames != null
        // && _signatureFieldNames.length > 0)
        else if (signatureFieldName != null) {
            // TextField exista: campul de semnatura va avea numele putin schimbat
            signatureFieldName = "___" + signatureFieldName + "___";
        } else // if(_signatureFieldNames == null || _signatureFieldNames.length == 0)
        {
            _rectSig = new Rectangle(500, 775, 600, 675);
            _nrPageSig = 1;
            signatureFieldName = "___signature2___";
        }
        return signatureFieldName;
    }

    public String doSignP12(String pdfIn, String pdfOut, PrivateKey key, Certificate[] chain) {
        PdfReader _pdfReader = null;
        PdfStamper _pdfStamper = null;
        String fileName = null;
        try {
            _pdfReader = new PdfReader(pdfIn);
            // Eliminare usage rights din PDF. Dispare eroarea:
            // "this document enabled extended features in adobe reader. the document has
            // been changed since..."
            // _pdfReader.removeUsageRights();
            // citire certificat
            // adaugare camp semnatura
            String signatureFieldName = setSignature(_pdfReader);
            // if(_signatureFieldNames != null
            // && _signatureFieldNames.length > 0)
            {
                fileName = pdfOut + ".tmp";
                _pdfStamper = new PdfStamper(_pdfReader, new FileOutputStream(fileName));
                // modificare PDF in mod append. Dispare eroarea:
                // "this document enabled extended features in adobe reader. the document has
                // been changed since..."
                // _pdfStamper = new PdfStamper(_pdfReader,
                // new FileOutputStream(fileName), '\0', true);
                PdfFormField sig = PdfFormField.createSignature(_pdfStamper.getWriter());
                // sig.setWidget(new Rectangle(400, 90, 550, 140), null);
                // sig.setWidget(rect, null);
                sig.setWidget(_rectSig, PdfAnnotation.HIGHLIGHT_INVERT);
                sig.setFlags(PdfAnnotation.FLAGS_PRINT);
                sig.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
                sig.setFieldName(signatureFieldName);
                // sig.setPage(1);
                _pdfStamper.addAnnotation(sig, _nrPageSig);
                _pdfStamper.close();
                _pdfReader.close();
                _pdfReader = new PdfReader(fileName);
            }
            // adaugare semnatura
            _pdfStamper = PdfStamper.createSignature(_pdfReader, new FileOutputStream(pdfOut), '\0',
                    new File(pdfOut + ".dmp"));
            PdfSignatureAppearance appearance = _pdfStamper.getSignatureAppearance();
            // if(_signatureFieldNames != null
            // && _signatureFieldNames.length > 0)
            {
                appearance.setReason(_signatureReason);
                // appearance.setLocation(signatureFieldName);
                appearance.setVisibleSignature(signatureFieldName);
            }
            // Creating the signature
            appearance.setCrypto(key, chain, null, PdfSignatureAppearance.SELF_SIGNED);
            // BouncyCastleProvider provider = new BouncyCastleProvider();
            // Security.addProvider(provider);
            // ExternalSignature signature =
            // new PrivateKeySignature(key, DigestAlgorithms.SHA1, provider.getName());
            // ExternalDigest digest = new BouncyCastleDigest();
            // MakeSignature.signDetached(appearance, digest, signature, _chain,
            // null, null, null, 0, CryptoStandard.CADES);
            _pdfStamper.close();
            _pdfReader.close();
            if (fileName != null) {
                (new File(fileName)).delete();
            }
            (new File(pdfOut + ".dmp")).delete();
        } catch (Throwable e) {
            return "eroare semnare cu certificat '" + _library + "': " + e.toString();
        }
        return null;
    }

    private static void logError(int code, Object msg) {
        if (msg instanceof String) {
            LogTrace.log("modul Sign; eroare=" + Integer.toString(code) + ": " + msg, 2);
        } else {
            Throwable ex = (Throwable) msg;
            StackTraceElement[] stack = ex.getStackTrace();
            LogTrace.log("modul Sign; eroare=" + Integer.toString(code) + ": " + ex.toString(), 2);
            for (StackTraceElement el : stack) {
                LogTrace.log(el.toString(), 3);
            }
        }
    }

    public class CertAlias {
        public String _alias;
        public X509Certificate _cert;

        public CertAlias(String alias, X509Certificate cert) {
            _alias = alias;
            _cert = cert;
        }

        @Override
        public String toString() {
            return _alias;// + _cert.getIssuerDN().getName();
        }
    }
}
