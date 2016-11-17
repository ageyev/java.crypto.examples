import java.security.Provider;
import java.security.Security;

/*
* see:
* http://stackoverflow.com/questions/14903539/what-specific-hash-algorithm-does-messagedigest-getinstancesha-return
* Algorithms Supported in this JCE
* */

public class JceLook {

    public static void main(String[] args) {
        System.out.println("Algorithms Supported in this JCE.");
        System.out.println("====================");
        // heading
        System.out.println("Provider: type.algorithm -> className" + "\n  aliases:" + "\n  attributes:\n");
        // discover providers
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println("<><><>" + provider + "<><><>\n");
            // discover services of each provider
            for (Provider.Service service : provider.getServices()) {
                System.out.println(service);
            }
            System.out.println();
        }
    }
}