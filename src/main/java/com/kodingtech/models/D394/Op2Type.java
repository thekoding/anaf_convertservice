//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.02.13 at 04:09:50 PM EET 
//

package com.kodingtech.models.D394;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

import com.google.gson.annotations.SerializedName;

/**
 * <p>
 * Java class for Op2Type complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="Op2Type">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="tip_op2" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}Str_tipOperatieSType" />
 *       &lt;attribute name="luna" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntInt1_12SType" />
 *       &lt;attribute name="nrAMEF" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz4SType" />
 *       &lt;attribute name="nrBF" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="total" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="baza20" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="baza9" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="baza5" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="TVA20" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="TVA9" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="TVA5" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="baza19" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *       &lt;attribute name="TVA19" use="required" type="{mfp:anaf:dgti:d394:declaratie:v3}IntPoz15SType" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Op2Type")
public class Op2Type {
    @SerializedName("tip_op2")
    @XmlAttribute(name = "tip_op2", required = true)
    protected StrTipOperatieSType tipOp2;
    @XmlAttribute(name = "luna", required = true)
    protected int luna;
    @XmlAttribute(name = "nrAMEF")
    protected Integer nrAMEF;
    @XmlAttribute(name = "nrBF")
    protected Long nrBF;
    @XmlAttribute(name = "total", required = true)
    protected long total;
    @XmlAttribute(name = "baza20", required = true)
    protected long baza20;
    @XmlAttribute(name = "baza9", required = true)
    protected long baza9;
    @XmlAttribute(name = "baza5", required = true)
    protected long baza5;
    @XmlAttribute(name = "TVA20", required = true)
    protected long tva20;
    @XmlAttribute(name = "TVA9", required = true)
    protected long tva9;
    @XmlAttribute(name = "TVA5", required = true)
    protected long tva5;
    @XmlAttribute(name = "baza19", required = true)
    protected long baza19;
    @XmlAttribute(name = "TVA19", required = true)
    protected long tva19;

    /**
     * Gets the value of the tipOp2 property.
     * 
     * @return possible object is {@link StrTipOperatieSType }
     * 
     */
    public StrTipOperatieSType getTipOp2() {
        return tipOp2;
    }

    /**
     * Sets the value of the tipOp2 property.
     * 
     * @param value allowed object is {@link StrTipOperatieSType }
     * 
     */
    public void setTipOp2(StrTipOperatieSType value) {
        this.tipOp2 = value;
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
     * Gets the value of the nrAMEF property.
     * 
     * @return possible object is {@link Integer }
     * 
     */
    public Integer getNrAMEF() {
        return nrAMEF;
    }

    /**
     * Sets the value of the nrAMEF property.
     * 
     * @param value allowed object is {@link Integer }
     * 
     */
    public void setNrAMEF(Integer value) {
        this.nrAMEF = value;
    }

    /**
     * Gets the value of the nrBF property.
     * 
     * @return possible object is {@link Long }
     * 
     */
    public Long getNrBF() {
        return nrBF;
    }

    /**
     * Sets the value of the nrBF property.
     * 
     * @param value allowed object is {@link Long }
     * 
     */
    public void setNrBF(Long value) {
        this.nrBF = value;
    }

    /**
     * Gets the value of the total property.
     * 
     */
    public long getTotal() {
        return total;
    }

    /**
     * Sets the value of the total property.
     * 
     */
    public void setTotal(long value) {
        this.total = value;
    }

    /**
     * Gets the value of the baza20 property.
     * 
     */
    public long getBaza20() {
        return baza20;
    }

    /**
     * Sets the value of the baza20 property.
     * 
     */
    public void setBaza20(long value) {
        this.baza20 = value;
    }

    /**
     * Gets the value of the baza9 property.
     * 
     */
    public long getBaza9() {
        return baza9;
    }

    /**
     * Sets the value of the baza9 property.
     * 
     */
    public void setBaza9(long value) {
        this.baza9 = value;
    }

    /**
     * Gets the value of the baza5 property.
     * 
     */
    public long getBaza5() {
        return baza5;
    }

    /**
     * Sets the value of the baza5 property.
     * 
     */
    public void setBaza5(long value) {
        this.baza5 = value;
    }

    /**
     * Gets the value of the tva20 property.
     * 
     */
    public long getTVA20() {
        return tva20;
    }

    /**
     * Sets the value of the tva20 property.
     * 
     */
    public void setTVA20(long value) {
        this.tva20 = value;
    }

    /**
     * Gets the value of the tva9 property.
     * 
     */
    public long getTVA9() {
        return tva9;
    }

    /**
     * Sets the value of the tva9 property.
     * 
     */
    public void setTVA9(long value) {
        this.tva9 = value;
    }

    /**
     * Gets the value of the tva5 property.
     * 
     */
    public long getTVA5() {
        return tva5;
    }

    /**
     * Sets the value of the tva5 property.
     * 
     */
    public void setTVA5(long value) {
        this.tva5 = value;
    }

    /**
     * Gets the value of the baza19 property.
     * 
     */
    public long getBaza19() {
        return baza19;
    }

    /**
     * Sets the value of the baza19 property.
     * 
     */
    public void setBaza19(long value) {
        this.baza19 = value;
    }

    /**
     * Gets the value of the tva19 property.
     * 
     */
    public long getTVA19() {
        return tva19;
    }

    /**
     * Sets the value of the tva19 property.
     * 
     */
    public void setTVA19(long value) {
        this.tva19 = value;
    }

}
