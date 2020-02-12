package pdf;

import java.util.List;
import pdf.Sign.CertAlias;

public interface CertificateChooser {
    public CertAlias chooseCertificate(List col);

    public String chooseZipFile(String xmlFile, int zipOption);
}