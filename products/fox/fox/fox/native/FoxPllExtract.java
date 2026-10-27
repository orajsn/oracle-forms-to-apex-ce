import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.stream.*;
import oracle.forms.jdapi.*;

/** Read-only Oracle JDAPI adapter. Does not compile, save, or connect to a DB.
 * FOX library XML is a normalized source envelope, NOT Oracle Forms XML/PLD.
 * Oracle implementation libraries are supplied by the local installation.
 */
public final class FoxPllExtract {
    static final String NS = "urn:fox:forms-library:v1";
    static final int LIMIT = 5 * 1024 * 1024;
    record Unit(String name, int type, String text, String hash) {}
    record Library(String name, String location, int source) {}

    static String clean(String value) {
        if (value == null) return "";
        String s = value.replace("\r\n", "\n").replace('\r', '\n');
        if (s.codePoints().anyMatch(c -> !(c == 9 || c == 10 || c == 13 ||
                (c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD) ||
                (c >= 0x10000 && c <= 0x10FFFF)))) {
            throw new IllegalArgumentException("Non-XML character in source");
        }
        return s;
    }

    static String hash(String s) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    static void export(Path input, Path output) throws Exception {
        if (Files.exists(output) || !Files.isRegularFile(input)) throw new IllegalArgumentException();
        // Fail closed when Oracle cannot load an attached library; do not claim
        // missing attachments were preserved if the native loader dropped them.
        Jdapi.setFailLibraryLoad(true);
        PlsqlModule module = PlsqlModule.open(input.toFile());
        if (Jdapi.isConnectedToDatabase()) throw new IllegalStateException();
        List<Unit> units = new ArrayList<>();
        List<Library> libraries = new ArrayList<>();
        int bytes = 0;
        JdapiIterator it = module.getProgramUnits();
        while (it.hasNext()) {
            ProgramUnit pu = (ProgramUnit) it.next();
            String text = clean(pu.getProgramUnitText());
            if (text.isBlank()) throw new IllegalArgumentException("Missing program-unit source");
            bytes += text.getBytes(StandardCharsets.UTF_8).length;
            if (bytes > LIMIT || units.size() >= 10000) throw new IllegalArgumentException();
            units.add(new Unit(clean(pu.getName()), pu.getProgramUnitType(), text, hash(text)));
        }
        if (units.isEmpty()) throw new IllegalArgumentException("No readable units");
        it = module.getAttachedLibraries();
        while (it.hasNext()) {
            AttachedLibrary lib = (AttachedLibrary) it.next();
            if (libraries.size() >= 1000) throw new IllegalArgumentException();
            libraries.add(new Library(clean(lib.getName()), clean(lib.getLibraryLocation()), lib.getLibrarySource()));
        }
        try (var stream = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW)) {
            XMLStreamWriter x = XMLOutputFactory.newFactory().createXMLStreamWriter(stream, "UTF-8");
            x.writeStartDocument("UTF-8", "1.0");
            x.writeStartElement("Module"); x.writeDefaultNamespace(NS);
            x.writeAttribute("Format", "FOX-JDAPI-LIBRARY-1");
            x.writeAttribute("OracleProductVersion", Long.toString(Jdapi.getProductVersion()));
            x.writeAttribute("DatabaseConnected", "false");
            x.writeAttribute("TextNormalization", "CRLF-and-CR-to-LF");
            x.writeStartElement("LibraryModule");
            x.writeAttribute("Name", clean(module.getName()));
            x.writeAttribute("SourceFile", input.getFileName().toString());
            x.writeAttribute("ProgramUnitCount", Integer.toString(units.size()));
            x.writeAttribute("AttachedLibraryCount", Integer.toString(libraries.size()));
            for (Library lib : libraries) {
                x.writeEmptyElement("AttachedLibrary");
                x.writeAttribute("Name", lib.name());
                x.writeAttribute("LibraryLocation", lib.location());
                x.writeAttribute("LibrarySource", Integer.toString(lib.source()));
            }
            for (Unit pu : units) {
                x.writeStartElement("ProgramUnit");
                x.writeAttribute("Name", pu.name());
                x.writeAttribute("ProgramUnitType", Integer.toString(pu.type()));
                x.writeAttribute("TextSHA256", pu.hash());
                x.writeStartElement("ProgramUnitText");
                x.writeCharacters(pu.text());
                x.writeEndElement(); x.writeEndElement();
            }
            x.writeEndElement(); x.writeEndElement(); x.writeEndDocument(); x.close();
        }
    }

    public static void main(String[] args) {
        int code = 0;
        try {
            if (args.length != 2) throw new IllegalArgumentException();
            export(Path.of(args[0]), Path.of(args[1]));
        } catch (Exception | LinkageError e) {
            // Native messages may contain confidential source or paths.
            System.err.println("FOX_PLL_EXTRACTION_FAILED"); code = 1;
        } finally {
            try { Jdapi.shutdown(); } catch (Exception | LinkageError e) { code = 1; }
        }
        System.exit(code);
    }
}
