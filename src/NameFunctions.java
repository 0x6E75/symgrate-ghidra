/* ###
 * Simple query for Symgrate.com.  If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to recover Thumb2 function names. RENAMES ALL FUNCTIONS IT FINDS.
//@category    Symgrate
//@author      Travis Goodspeed and EVM
//@menupath    Tools.Symgrate.Name Functions



import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;

import static ghidra.program.model.symbol.SourceType.*;


public class NameFunctions extends GhidraScript{
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    //Perform the HTTPS query.
    String queryjfns(String suffix) throws InterruptedException, IOException {
        String requestURL = "https://symgrate.com/jfns?"+suffix;
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(requestURL))
                .setHeader("User-Agent", "Ghidra "+getGhidraVersion()) // add request header
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // print response headers
        HttpHeaders headers = response.headers();
        headers.map().forEach((k, v) -> System.out.println(k + ":" + v));

        return response.body();
    }

    boolean appendPlateComment(Address addr, String comment) {
        String oldComment = getPlateComment(addr);

        if (oldComment == null) {
            return setPlateComment(addr, comment);
        } else if (oldComment.contains(comment)) {
            return true;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(oldComment);
        sb.append("\n");
        sb.append(comment);

        return setPlateComment(addr, sb.toString());
    }

    //Imports one label, if the function isn't already named.
    void importlabel(String adr, JsonObject obj){
        String name=obj.get("Name").getAsString();
        String filename = obj.get("Filename").getAsString();
        Function f=getFunctionAt(toAddr(adr));

        //We're mostly trying to replace the DEFAULT entries.
        println(String.format("%s: %s (from %s)", adr, name, filename));
        //if(f.getSignatureSource()==DEFAULT){
            try {
                f.setName(name, IMPORTED);
                appendPlateComment(f.getEntryPoint(), String.format("symgrate: name \"%s\" from \"%s\"", name, filename));
            } catch (DuplicateNameException e) {
                println("Failed to import duplicate name: "+name+" at "+adr);
            } catch (InvalidInputException e) {
                e.printStackTrace();
            }
        //} else {
        //    println(String.format("%s is already named %s at %s", name, f.getName(), adr));
        //}
    }

    //Imports a JSON string from the API query.
    void importresult(String json){
        Gson gson = new Gson();
        JsonObject obj = gson.fromJson(json, JsonObject.class);
        Set<String> keys = obj.keySet();
        for (String name : keys) {
            importlabel(name, obj.getAsJsonObject(name));
        }
    }

    String byteString(Function function) throws MemoryAccessException {
        //Grab eighteen bytes.
        byte[] bytes=getBytes(function.getEntryPoint(), 18);
        StringBuilder sb=new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(String.format("%02x", ((int) aByte) & 0xFF));
        }
        return sb.toString();
    }

    @Override
    protected void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int count = fm.getFunctionCount();
        monitor.initialize(count);
        Function f = getFirstFunction();
        StringBuilder q=new StringBuilder();

        for(int i=0; f!=null && !monitor.isCancelled(); i++){
            String adr=f.getEntryPoint().toString();

            try {
                long funcSize = (f.getBody().getMaxAddress().getOffset() + 1) - f.getBody().getMinAddress().getOffset();
                if(funcSize >= 18){
                    String data=byteString(f);
                    q.append(adr);
                    q.append("=");
                    q.append(data);
                    q.append("&");
                }
            } catch (MemoryAccessException e) {
                println(String.format("Could not load function bytes at %s", adr));
                i -= 1;
            }

            f=getFunctionAfter(f);

            if((i&0xFF)==0xFF || f==null){
                importresult(queryjfns(q.toString()));
                q=new StringBuilder();
                monitor.setProgress(i);
            }
        }
        println("Symbol recovery complete.");
    }
}
