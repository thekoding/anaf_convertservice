//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.02.13 at 04:09:50 PM EET 
//

package com.kodingtech.models.D394;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.google.gson.annotations.SerializedName;

/**
 * <p>
 * Java class for Declaratie394Type complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="Declaratie394Type">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="informatii" type="{mfp:anaf:dgti:d394:declaratie:v3}InformatiiType"/>
 *         &lt;element name="rezumat1" type="{mfp:anaf:dgti:d394:declaratie:v3}Rezumat1Type" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="rezumat2" type="{mfp:anaf:dgti:d394:declaratie:v3}Rezumat2Type" maxOccurs="5" minOccurs="0"/>
 *         &lt;element name="serieFacturi" type="{mfp:anaf:dgti:d394:declaratie:v3}SerieFacturiType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="lista" type="{mfp:anaf:dgti:d394:declaratie:v3}ListaType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="facturi" type="{mfp:anaf:dgti:d394:declaratie:v3}FacturiType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="op1" type="{mfp:anaf:dgti:d394:declaratie:v3}Op1Type" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="op2" type="{mfp:anaf:dgti:d394:declaratie:v3}Op2Type" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="luna" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt1_12SType" />
 *       &lt;attribute name="an" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt2016_2100SType" />
 *       &lt;attribute name="tip_D394" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str_listaTipD394SType" />
 *       &lt;attribute name="sistemTVA" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt0_1SType" />
 *       &lt;attribute name="op_efectuate" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt0_1SType" />
 *       &lt;attribute name="cui" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}CuiSType" />
 *       &lt;attribute name="caen" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str_coduriCaenSType" />
 *       &lt;attribute name="den" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str200" />
 *       &lt;attribute name="adresa" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str1000" />
 *       &lt;attribute name="telefon" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str15" />
 *       &lt;attribute name="fax" type="{mfp:anaf:dgti:d394:declaratie:v3}Str15" />
 *       &lt;attribute name="mail" type="{mfp:anaf:dgti:d394:declaratie:v3}Str200" />
 *       &lt;attribute name="totalPlata_A" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntNeg15SType" />
 *       &lt;attribute name="cifR" type="{mfp:anaf:dgti:d394:declaratie:v3}CifSType" />
 *       &lt;attribute name="denR" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str200" />
 *       &lt;attribute name="functie_reprez" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str100" />
 *       &lt;attribute name="adresaR" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str1000" />
 *       &lt;attribute name="telefonR" type="{mfp:anaf:dgti:d394:declaratie:v3}Str15" />
 *       &lt;attribute name="faxR" type="{mfp:anaf:dgti:d394:declaratie:v3}Str15" />
 *       &lt;attribute name="mailR" type="{mfp:anaf:dgti:d394:declaratie:v3}Str200" />
 *       &lt;attribute name="tip_intocmit" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt0_1SType" />
 *       &lt;attribute name="den_intocmit" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str75" />
 *       &lt;attribute name="cif_intocmit" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz13SType" />
 *       &lt;attribute name="calitate_intocmit" type="{mfp:anaf:dgti:d394:declaratie:v3}Str75" />
 *       &lt;attribute name="functie_intocmit" type="{mfp:anaf:dgti:d394:declaratie:v3}Str75" />
 *       &lt;attribute name="optiune" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt0_1SType" />
 *       &lt;attribute name="schimb_optiune" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt1_1SType" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.NONE)
@XmlRootElement(namespace = "mfp:anaf:dgti:d394:declaratie:v3", name="declaratie394")
@XmlType(name = "Declaratie394Type", propOrder = { "informatii", "rezumat1", "rezumat2", "serieFacturi", "lista",
        "facturi", "op1", "op2" })
public class Declaratie394Type {

    protected String key;

    protected String keyPassword;

    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected InformatiiType informatii;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<Rezumat1Type> rezumat1;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<Rezumat2Type> rezumat2;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<SerieFacturiType> serieFacturi;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<ListaType> lista;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<FacturiType> facturi;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<Op1Type> op1;
    @XmlElement(required = true, namespace = "mfp:anaf:dgti:d394:declaratie:v3")
    protected List<Op2Type> op2;
    @XmlAttribute(name = "luna", required = true)
    protected int luna;
    @XmlAttribute(name = "an", required = true)
    protected int an;
    @SerializedName("tip_D394")
    @XmlAttribute(name = "tip_D394", required = true)
    protected StrListaTipD394SType tipD394;
    @XmlAttribute(name = "sistemTVA", required = true)
    protected int sistemTVA;
    @SerializedName("op_efectuate")
    @XmlAttribute(name = "op_efectuate", required = true)
    protected int opEfectuate;
    @XmlAttribute(name = "cui", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    protected String cui;
    @XmlAttribute(name = "caen", required = true)
    protected String caen;
    @XmlAttribute(name = "den", required = true)
    protected String den;
    @XmlAttribute(name = "adresa", required = true)
    protected String adresa;
    @XmlAttribute(name = "telefon", required = true)
    protected String telefon;
    @XmlAttribute(name = "fax")
    protected String fax;
    @XmlAttribute(name = "mail")
    protected String mail;
    @SerializedName("totalPlata_A")
    @XmlAttribute(name = "totalPlata_A", required = true)
    protected long totalPlataA;
    @XmlAttribute(name = "cifR")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    protected String cifR;
    @XmlAttribute(name = "denR", required = true)
    protected String denR;
    @SerializedName("functie_reprez")
    @XmlAttribute(name = "functie_reprez", required = true)
    protected String functieReprez;
    @XmlAttribute(name = "adresaR", required = true)
    protected String adresaR;
    @XmlAttribute(name = "telefonR")
    protected String telefonR;
    @XmlAttribute(name = "faxR")
    protected String faxR;
    @XmlAttribute(name = "mailR")
    protected String mailR;
    @SerializedName("tip_intocmit")
    @XmlAttribute(name = "tip_intocmit", required = true)
    protected int tipIntocmit;
    @SerializedName("den_intocmit")
    @XmlAttribute(name = "den_intocmit", required = true)
    protected String denIntocmit;
    @SerializedName("cif_intocmit")
    @XmlAttribute(name = "cif_intocmit", required = true)
    protected long cifIntocmit;
    @SerializedName("calitate_intocmit")
    @XmlAttribute(name = "calitate_intocmit")
    protected String calitateIntocmit;
    @SerializedName("functie_intocmit")
    @XmlAttribute(name = "functie_intocmit")
    protected String functieIntocmit;
    @XmlAttribute(name = "optiune", required = true)
    protected int optiune;
    @SerializedName("schimb_optiune")
    @XmlAttribute(name = "schimb_optiune")
    protected Integer schimbOptiune;

    public String getKey() {
        return key;
    }

    public void setKey(String value) {
        key = value;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String value) {
        keyPassword = value;
    }

    /**
     * Gets the value of the informatii property.
     * 
     * @return possible object is {@link InformatiiType }
     * 
     */
    public InformatiiType getInformatii() {
        return informatii;
    }

    /**
     * Sets the value of the informatii property.
     * 
     * @param value allowed object is {@link InformatiiType }
     * 
     */
    public void setInformatii(InformatiiType value) {
        this.informatii = value;
    }

    /**
     * Gets the value of the rezumat1 property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the rezumat1 property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getRezumat1().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link Rezumat1Type
     * }
     * 
     * 
     */
    public List<Rezumat1Type> getRezumat1() {
        if (rezumat1 == null) {
            rezumat1 = new ArrayList<Rezumat1Type>();
        }
        return this.rezumat1;
    }

    /**
     * Gets the value of the rezumat2 property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the rezumat2 property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getRezumat2().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link Rezumat2Type
     * }
     * 
     * 
     */
    public List<Rezumat2Type> getRezumat2() {
        if (rezumat2 == null) {
            rezumat2 = new ArrayList<Rezumat2Type>();
        }
        return this.rezumat2;
    }

    /**
     * Gets the value of the serieFacturi property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the serieFacturi property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getSerieFacturi().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SerieFacturiType }
     * 
     * 
     */
    public List<SerieFacturiType> getSerieFacturi() {
        if (serieFacturi == null) {
            serieFacturi = new ArrayList<SerieFacturiType>();
        }
        return this.serieFacturi;
    }

    /**
     * Gets the value of the lista property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the lista property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getLista().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link ListaType }
     * 
     * 
     */
    public List<ListaType> getLista() {
        if (lista == null) {
            lista = new ArrayList<ListaType>();
        }
        return this.lista;
    }

    /**
     * Gets the value of the facturi property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the facturi property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getFacturi().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link FacturiType }
     * 
     * 
     */
    public List<FacturiType> getFacturi() {
        if (facturi == null) {
            facturi = new ArrayList<FacturiType>();
        }
        return this.facturi;
    }

    /**
     * Gets the value of the op1 property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the op1 property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getOp1().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link Op1Type }
     * 
     * 
     */
    public List<Op1Type> getOp1() {
        if (op1 == null) {
            op1 = new ArrayList<Op1Type>();
        }
        return this.op1;
    }

    /**
     * Gets the value of the op2 property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot.
     * Therefore any modification you make to the returned list will be present
     * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
     * for the op2 property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getOp2().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link Op2Type }
     * 
     * 
     */
    public List<Op2Type> getOp2() {
        if (op2 == null) {
            op2 = new ArrayList<Op2Type>();
        }
        return this.op2;
    }

    /**
     * Gets the value of the luna property.
     * 
     */
    public int getLuna() {
        return luna;
    }

    /**
     * Sets the value of the luna property.
     * 
     */
    public void setLuna(int value) {
        this.luna = value;
    }

    /**
     * Gets the value of the an property.
     * 
     */
    public int getAn() {
        return an;
    }

    /**
     * Sets the value of the an property.
     * 
     */
    public void setAn(int value) {
        this.an = value;
    }

    /**
     * Gets the value of the tipD394 property.
     * 
     * @return possible object is {@link StrListaTipD394SType }
     * 
     */
    public StrListaTipD394SType getTipD394() {
        return tipD394;
    }

    /**
     * Sets the value of the tipD394 property.
     * 
     * @param value allowed object is {@link StrListaTipD394SType }
     * 
     */
    public void setTipD394(StrListaTipD394SType value) {
        this.tipD394 = value;
    }

    /**
     * Gets the value of the sistemTVA property.
     * 
     */
    public int getSistemTVA() {
        return sistemTVA;
    }

    /**
     * Sets the value of the sistemTVA property.
     * 
     */
    public void setSistemTVA(int value) {
        this.sistemTVA = value;
    }

    /**
     * Gets the value of the opEfectuate property.
     * 
     */
    public int getOpEfectuate() {
        return opEfectuate;
    }

    /**
     * Sets the value of the opEfectuate property.
     * 
     */
    public void setOpEfectuate(int value) {
        this.opEfectuate = value;
    }

    /**
     * Gets the value of the cui property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getCui() {
        return cui;
    }

    /**
     * Sets the value of the cui property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setCui(String value) {
        this.cui = value;
    }

    /**
     * Gets the value of the caen property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getCaen() {
        return caen;
    }

    /**
     * Sets the value of the caen property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setCaen(String value) {
        this.caen = value;
    }

    /**
     * Gets the value of the den property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getDen() {
        return den;
    }

    /**
     * Sets the value of the den property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setDen(String value) {
        this.den = value;
    }

    /**
     * Gets the value of the adresa property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getAdresa() {
        return adresa;
    }

    /**
     * Sets the value of the adresa property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setAdresa(String value) {
        this.adresa = value;
    }

    /**
     * Gets the value of the telefon property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getTelefon() {
        return telefon;
    }

    /**
     * Sets the value of the telefon property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setTelefon(String value) {
        this.telefon = value;
    }

    /**
     * Gets the value of the fax property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getFax() {
        return fax;
    }

    /**
     * Sets the value of the fax property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setFax(String value) {
        this.fax = value;
    }

    /**
     * Gets the value of the mail property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getMail() {
        return mail;
    }

    /**
     * Sets the value of the mail property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setMail(String value) {
        this.mail = value;
    }

    /**
     * Gets the value of the totalPlataA property.
     * 
     */
    public long getTotalPlataA() {
        return totalPlataA;
    }

    /**
     * Sets the value of the totalPlataA property.
     * 
     */
    public void setTotalPlataA(long value) {
        this.totalPlataA = value;
    }

    /**
     * Gets the value of the cifR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getCifR() {
        return cifR;
    }

    /**
     * Sets the value of the cifR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setCifR(String value) {
        this.cifR = value;
    }

    /**
     * Gets the value of the denR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getDenR() {
        return denR;
    }

    /**
     * Sets the value of the denR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setDenR(String value) {
        this.denR = value;
    }

    /**
     * Gets the value of the functieReprez property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getFunctieReprez() {
        return functieReprez;
    }

    /**
     * Sets the value of the functieReprez property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setFunctieReprez(String value) {
        this.functieReprez = value;
    }

    /**
     * Gets the value of the adresaR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getAdresaR() {
        return adresaR;
    }

    /**
     * Sets the value of the adresaR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setAdresaR(String value) {
        this.adresaR = value;
    }

    /**
     * Gets the value of the telefonR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getTelefonR() {
        return telefonR;
    }

    /**
     * Sets the value of the telefonR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setTelefonR(String value) {
        this.telefonR = value;
    }

    /**
     * Gets the value of the faxR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getFaxR() {
        return faxR;
    }

    /**
     * Sets the value of the faxR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setFaxR(String value) {
        this.faxR = value;
    }

    /**
     * Gets the value of the mailR property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getMailR() {
        return mailR;
    }

    /**
     * Sets the value of the mailR property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setMailR(String value) {
        this.mailR = value;
    }

    /**
     * Gets the value of the tipIntocmit property.
     * 
     */
    public int getTipIntocmit() {
        return tipIntocmit;
    }

    /**
     * Sets the value of the tipIntocmit property.
     * 
     */
    public void setTipIntocmit(int value) {
        this.tipIntocmit = value;
    }

    /**
     * Gets the value of the denIntocmit property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getDenIntocmit() {
        return denIntocmit;
    }

    /**
     * Sets the value of the denIntocmit property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setDenIntocmit(String value) {
        this.denIntocmit = value;
    }

    /**
     * Gets the value of the cifIntocmit property.
     * 
     */
    public long getCifIntocmit() {
        return cifIntocmit;
    }

    /**
     * Sets the value of the cifIntocmit property.
     * 
     */
    public void setCifIntocmit(long value) {
        this.cifIntocmit = value;
    }

    /**
     * Gets the value of the calitateIntocmit property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getCalitateIntocmit() {
        return calitateIntocmit;
    }

    /**
     * Sets the value of the calitateIntocmit property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setCalitateIntocmit(String value) {
        this.calitateIntocmit = value;
    }

    /**
     * Gets the value of the functieIntocmit property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getFunctieIntocmit() {
        return functieIntocmit;
    }

    /**
     * Sets the value of the functieIntocmit property.
     * 
     * @param value allowed object is {@link String }
     * 
     */
    public void setFunctieIntocmit(String value) {
        this.functieIntocmit = value;
    }

    /**
     * Gets the value of the optiune property.
     * 
     */
    public int getOptiune() {
        return optiune;
    }

    /**
     * Sets the value of the optiune property.
     * 
     */
    public void setOptiune(int value) {
        this.optiune = value;
    }

    /**
     * Gets the value of the schimbOptiune property.
     * 
     * @return possible object is {@link Integer }
     * 
     */
    public Integer getSchimbOptiune() {
        return schimbOptiune;
    }

    /**
     * Sets the value of the schimbOptiune property.
     * 
     * @param value allowed object is {@link Integer }
     * 
     */
    public void setSchimbOptiune(Integer value) {
        this.schimbOptiune = value;
    }

}
