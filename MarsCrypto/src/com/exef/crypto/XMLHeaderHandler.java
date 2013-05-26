package com.exef.crypto;

import com.exef.utils.Logger;
import com.thoughtworks.xstream.XStream;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 *
 * @author Filip
 */
public class XMLHeaderHandler {

    private XStream xstream = new XStream();
    private CryptoProperies xmlHeader = new CryptoProperies();
    private String propertiesXML;
    private String rootName = "encryptedFile";

    public XMLHeaderHandler() {
        xstream.alias(rootName, CryptoProperies.class);
    }

    public void setCryptoProperies(CryptoProperies header) {
        this.xmlHeader = header;
    }

    public String getHeaderXMLString() {
        return xstream.toXML(xmlHeader);
    }

    public void makeXMLHeaderFile(String path) {
        try {
            try (BufferedWriter out = new BufferedWriter(new FileWriter(path))) {
                out.write(this.getHeaderXMLString());
                out.newLine();
            }
        } catch (IOException e) {
            Logger.addMessage("Exception in MakeXMLHeaderFile: " + e);
        }
    }

    public CryptoProperies takeXMLHeaderFromFile(String path) {
        propertiesXML = new String();
        removeHeaderFromFile(path);
        return getHeaderXMLObject(propertiesXML);
    }

    private int removeFirstLine(String path) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
            long writePosition = raf.getFilePointer();
            propertiesXML += raf.readLine();

            if (!propertiesXML.contains("<" + rootName + ">")) {
                return -1;
            }

            long readPosition = raf.getFilePointer();

            byte[] buff = new byte[1024];
            int n;
            while (-1 != (n = raf.read(buff))) {
                raf.seek(writePosition);
                raf.write(buff, 0, n);
                readPosition += n;
                writePosition += n;
                raf.seek(readPosition);
            }
            raf.setLength(writePosition);
            return 0;
        }
    }

    private void removeHeaderFromFile(String path) {
        try {
            while (!propertiesXML.contains("</" + rootName + ">")) {
                if (removeFirstLine(path) == -1) {
                    CryptoProperies cp = new CryptoProperies();
                    cp.error = "error";
                    propertiesXML = xstream.toXML(cp);
                    break;
                }
            }
        } catch (IOException ex) {
            Logger.addMessage("Exception in removeHeaderFromFile: " + ex);
        }
    }

    private CryptoProperies getHeaderXMLObject(String xml) {
        return (CryptoProperies) xstream.fromXML(xml);
    }

    public static void main(String[] args) {
        XMLHeaderHandler header = new XMLHeaderHandler();
        System.out.println(header.getHeaderXMLString());
        System.out.println(header.getHeaderXMLObject(header.getHeaderXMLString()).mode);
    }
}
