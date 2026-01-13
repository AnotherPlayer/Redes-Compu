import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Funciones de apoyo para calcular datos de direccionamiento IPv4.
 * Cada operación solicitada en las instrucciones se expone como un método.
 */
public class IpCalculatorOperations {

    private static final int MAX_LIST_LIMIT = 1024;

    public static String getIpClass(String ip) {
        int[] octets = parseOctets(ip);
        if (!isValidOctets(octets)) {
            return "Desconocida";
        }
        int first = octets[0];
        if (first >= 1 && first <= 126) {
            return "A";
        }
        if (first >= 128 && first <= 191) {
            return "B";
        }
        if (first >= 192 && first <= 223) {
            return "C";
        }
        if (first >= 224 && first <= 239) {
            return "D";
        }
        return "E";
    }

    public static String getDefaultMask(String ip) {
        int prefix = getDefaultPrefix(ip);
        return prefix > 0 ? getMaskFromPrefix(prefix) : "";
    }

    public static int getDefaultPrefix(String ip) {
        int[] octets = parseOctets(ip);
        if (!isValidOctets(octets)) {
            return -1;
        }
        int first = octets[0];
        if (first >= 1 && first <= 126) {
            return 8;
        }
        if (first >= 128 && first <= 191) {
            return 16;
        }
        if (first >= 192 && first <= 223) {
            return 24;
        }
        return -1;
    }

    public static int calculatePrefixForHosts(int desiredHosts) {
        int target = Math.max(desiredHosts, 1);
        for (int hostBits = 2; hostBits <= 30; hostBits++) {
            long capacity = (1L << hostBits) - 2;
            if (capacity >= target) {
                return 32 - hostBits;
            }
        }
        return -1;
    }

    public static long calculateHostsPerSubnet(int prefix) {
        if (prefix < 0 || prefix > 32) {
            return 0;
        }
        int hostBits = 32 - prefix;
        if (hostBits <= 1) {
            return 0;
        }
        return (1L << hostBits) - 2;
    }

    public static long calculateSubnetCount(String ip, int prefix) {
        int defaultPrefix = getDefaultPrefix(ip);
        if (defaultPrefix < 0 || prefix < defaultPrefix || prefix > 32) {
            return 0;
        }
        int borrowed = prefix - defaultPrefix;
        if (borrowed == 0) {
            return 1;
        }
        long total = 1L << borrowed;
        return total <= 2 ? total : total - 2;
    }

    public static String getMaskFromPrefix(int prefix) {
        if (prefix < 0 || prefix > 32) {
            return "";
        }
        long mask = maskToLong(prefix);
        return fromLong(mask);
    }

    public static List<String> listSubnets(String ip, int prefix) {
        return listSubnets(ip, prefix, MAX_LIST_LIMIT);
    }

    public static List<String> listSubnets(String ip, int prefix, int limit) {
        int[] octets = parseOctets(ip);
        int defaultPrefix = getDefaultPrefix(ip);
        if (!isValidOctets(octets) || defaultPrefix < 0 || prefix < defaultPrefix || prefix > 32) {
            return Collections.emptyList();
        }

        long base = toLong(octets) & maskToLong(defaultPrefix);
        long step = 1L << (32 - prefix);
        long totalSubnets = calculateSubnetCount(ip, prefix);
        long items = Math.min(totalSubnets, Math.max(0, limit));
        List<String> result = new ArrayList<>();

        for (int i = 0; i < items; i++) {
            long network = base + (step * i);
            result.add((i + 1) + ". " + fromLong(network) + "/" + prefix);
        }
        return result;
    }

    public static List<String> listHostsForSubnet(String ip, int prefix, int subnetIndex) {
        return listHostsForSubnet(ip, prefix, subnetIndex, MAX_LIST_LIMIT);
    }

    public static List<String> listHostsForSubnet(String ip, int prefix, int subnetIndex, int limit) {
        int[] octets = parseOctets(ip);
        int defaultPrefix = getDefaultPrefix(ip);
        if (!isValidOctets(octets) || defaultPrefix < 0 || prefix < defaultPrefix || prefix > 32 || subnetIndex < 0) {
            return Collections.emptyList();
        }

        long base = toLong(octets) & maskToLong(defaultPrefix);
        long step = 1L << (32 - prefix);
        long usableHosts = calculateHostsPerSubnet(prefix);
        if (usableHosts <= 0) {
            return Collections.emptyList();
        }

        long subnetStart = base + (step * subnetIndex);
        long firstHost = subnetStart + 1;
        long lastHost = subnetStart + step - 2;
        long items = Math.min(usableHosts, Math.max(0, limit));

        List<String> hosts = new ArrayList<>();
        for (long offset = 0; offset < items && (firstHost + offset) <= lastHost; offset++) {
            hosts.add((offset + 1) + ". " + fromLong(firstHost + offset));
        }
        if (hosts.isEmpty()) {
            return Collections.emptyList();
        }
        if (lastHost > firstHost + items - 1) {
            hosts.add("... (" + usableHosts + " hosts totales)");
        }
        return hosts;
    }

    private static boolean isValidOctets(int[] octets) {
        return octets != null && octets.length == 4;
    }

    private static int[] parseOctets(String ip) {
        if (ip == null) {
            return null;
        }
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) {
            return null;
        }
        int[] octets = new int[4];
        try {
            for (int i = 0; i < 4; i++) {
                int value = Integer.parseInt(parts[i]);
                if (value < 0 || value > 255) {
                    return null;
                }
                octets[i] = value;
            }
        } catch (NumberFormatException ex) {
            return null;
        }
        return octets;
    }

    private static long toLong(int[] octets) {
        return ((long) octets[0] << 24)
                | ((long) octets[1] << 16)
                | ((long) octets[2] << 8)
                | (long) octets[3];
    }

    private static String fromLong(long value) {
        long a = (value >> 24) & 0xFF;
        long b = (value >> 16) & 0xFF;
        long c = (value >> 8) & 0xFF;
        long d = value & 0xFF;
        return a + "." + b + "." + c + "." + d;
    }

    private static long maskToLong(int prefix) {
        if (prefix == 0) {
            return 0;
        }
        return (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    }
}
