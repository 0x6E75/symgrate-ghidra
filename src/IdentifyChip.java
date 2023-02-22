/* ###
 * Simple query for Symgrate.com.  If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to a Thumb2 chip from its I/O Addresses.
//@category    Symgrate
//@author      Travis Goodspeed and EVM
//@menupath    Tools.Symgrate.Identify Chip

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class IdentifyChip extends GhidraScript {
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    //Perform the HTTPS query.
    String queryjregs(String suffix) throws InterruptedException, IOException {
        String requestURL = "https://symgrate.com/jregs?"+suffix;
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

    //Imports a JSON string from the API query.
    void importresult(String json){
        Gson gson = new Gson();
        JsonArray obj = gson.fromJson(json, JsonArray.class);
        for(int i=0; i<obj.size(); i++){
            JsonElement el=obj.get(i);
            JsonObject guess=el.getAsJsonObject();
            Set<String> keys = guess.keySet();
            String name=guess.get("Name").toString();
            println(name);
        }
    }


    @Override
    protected void run() throws Exception {
        StringBuilder q=new StringBuilder();

        Address peripheralsStart = getAddressFactory().getDefaultAddressSpace().getAddress(0x40000000);
        AddressSet peripheralAddrs = getAddressFactory().getAddressSet(peripheralsStart, peripheralsStart.add(0x10000000));

        ReferenceManager refMan = currentProgram.getReferenceManager();

        AddressIterator destIter = refMan.getReferenceDestinationIterator(peripheralAddrs, true);
        while (destIter.hasNext()) {
            Address destAddr = destIter.next();
            boolean read = false;
            boolean write = false;

            ReferenceIterator refIter = refMan.getReferencesTo(destAddr);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();

                if (ref.getReferenceType().isData()) {
                    read |= ref.getReferenceType().isRead();
                    write |= ref.getReferenceType().isWrite();
                }
            }

            q.append(String.format("0x%x=", destAddr.getOffset()));
            if (read || write) {
                if (read)
                    q.append("r");
                if (write)
                    q.append("w");
            } else {
                q.append("u");
            }
            q.append("&");
        }

        importresult(queryjregs(q.toString()));
    }
}
