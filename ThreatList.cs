using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Proliferation.Fatum;
using DatabaseAdapters;
using System.Data;
using System.Net;
using System.IO;
using System.Threading;

namespace ThreatIntelligence
{
    public class ThreatList
    {
        public static void processBlocklists(string connectionstring)
        {
            try
            {
                IntDatabase db = new ADOConnector(connectionstring, "Archlake");

                string SQL = "select * from Blocklists where Enabled = 1";

                DataTable dt = db.Execute(SQL);

                foreach (DataRow row in dt.Rows)
                {
                    WorkUnit(row, connectionstring);
                }

                db.Close();
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.Message);
                Console.Out.WriteLine(ex.StackTrace);
            }
        }

        private static async void WorkUnit(DataRow row, string connectionstring)
        {
            string Destination = @"C:\ThreatIntelligence\Daily\";
            string Archive = @"C:\ThreatIntelligence\Archive\";
            string Bad = @"C:\ThreatIntelligence\Bad\";

            if (!Directory.Exists(@"C:\ThreatIntelligence"))
            {
                Directory.CreateDirectory(@"C:\ThreatIntelligence");
                if (!Directory.Exists(Destination))
                {
                    Directory.CreateDirectory(Destination);
                }
                if (!Directory.Exists(Archive))
                {
                    Directory.CreateDirectory(Archive);
                }
                if (!Directory.Exists(Bad))
                {
                    Directory.CreateDirectory(Bad);
                }
            }
            long ID = Convert.ToInt64(row["ID"]);
            string URL = row["URL"].ToString();
            string Name = row["Name"].ToString();
            string Category = row["Category"] == DBNull.Value ? null : row["Category"].ToString();
            string Structure = row["Structure"] == DBNull.Value ? null : row["Structure"].ToString();
            string PreviousHash = row["PreviousHash"] == DBNull.Value ? null : row["PreviousHash"].ToString();
            long? PreviousLength = row["PreviousLength"] == DBNull.Value ? null : (long?)Convert.ToInt64(row["PreviousLength"]);
            int? PreviousCount = row["PreviousCount"] == DBNull.Value ? null : (int?)Convert.ToInt32(row["PreviousCount"]);
            DateTime? LastPoll = row["LastPoll"] == DBNull.Value ? null : (DateTime?)Convert.ToDateTime(row["LastPoll"]);

            try
            {
                string destinationFile = Destination + ID.ToString() + ".txt";

                using (var client = new WebClient())
                {
                    Console.Out.WriteLine("Downloading " + Name);
                    Console.Out.WriteLine("Destination: " + destinationFile);

                    if (File.Exists(destinationFile))
                    {
                        File.Delete(destinationFile);
                    }
                    client.DownloadFile(URL, destinationFile);
                }

                if (File.Exists(destinationFile))
                {
                    FileInfo fi = new FileInfo(destinationFile);
                    int hash = fi.GetHashCode();
                    long length = fi.Length;
                    Boolean valid = false;

                    if (length > 0)
                    {
                        if (PreviousCount != null)
                        {
                            PreviousCount++;
                        }
                        else
                        {
                            PreviousCount = 1;
                        }
                        valid = true;
                    }

                    if (PreviousHash != null)
                    {
                        if (PreviousHash.ToLower() == hash.ToString().ToLower())
                        {
                            if (PreviousLength.Value != length)
                            {
                                valid = false;
                                if (PreviousCount != null)
                                {
                                    PreviousCount++;
                                }
                                else
                                {
                                    PreviousCount = 1;
                                }
                            }
                        }
                        else
                        {
                            PreviousHash = fi.GetHashCode().ToString();
                            PreviousLength = fi.Length;
                            PreviousCount = 0;
                            valid = true;
                        }
                    }
                    else
                    {
                        PreviousHash = fi.GetHashCode().ToString();
                        PreviousLength = fi.Length;
                        PreviousCount = 0;
                        valid = true;
                    }

                    UpdateBlockedListEntry(connectionstring, PreviousHash, PreviousLength, PreviousCount, ID);

                    if (valid)
                    {
                        Tree parsedList = null;
                        Console.Out.WriteLine("Structure: " + Structure);
                        switch (Structure.ToLower())
                        {
                            case "hashcommentedlist":
                                parsedList = readHashCommentedList(Destination + ID.ToString() + ".txt");
                                break;
                            case "hashcommentedipandhostlist":
                                parsedList = readHashCommentedIPandHostList(Destination + ID.ToString() + ".txt");
                                break;
                        }

                        if (parsedList.leafnames.Count > 0)
                        {
                            // Insert into database

                            foreach (Tree current in parsedList.tree)
                            {
                                current.AddElement("ID", ID.ToString());
                                current.AddElement("LastObserved", DateTime.UtcNow.ToString("yyyy-mm-dd"));
                                await ProcessBlockedEntry(connectionstring, current, ID, 1);
                            }

                            Task.WaitAll();

                            // Move to Archive

                            File.Move(destinationFile, Archive + ID.ToString() + "." + DateTime.UtcNow.ToString("yyyymmddhhmmss") + ".txt");
                        }
                        else
                        {
                            File.Move(destinationFile, Bad + ID.ToString() + "." + DateTime.UtcNow.ToString("yyyymmddhhmmss") + ".txt");
                        }

                        parsedList.Dispose();
                    }
                    else
                    {
                        // Not recently updated, we ignore this file because it isn't new.
                        Console.WriteLine("Data is identical to previous poll, not processing.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.Message);
                Console.Out.WriteLine(ex.StackTrace);
            }
        }

        private static async Task ProcessBlockedEntry(string connectionstring, Tree entryvalue, long BlockListId, int recursionDepth)
        {
            Console.Out.Flush();
            if (isBlockedEntryValid(entryvalue))
            {
                Boolean successful = false;

                while (!successful)
                {
                    IntDatabase db = new ADOConnector(connectionstring, "Archlake");
                    try
                    {

                        if (CheckForExistingEntry(connectionstring, entryvalue))
                        {
                            UpdateDatabaseEntry(connectionstring, entryvalue);
                        }
                        else
                        {
                            InsertDatabaseEntry(connectionstring, entryvalue, BlockListId, recursionDepth);
                        }
                        successful = true;
                    }
                    catch (Exception xyz)
                    {
                        successful = false;
                        Thread.Sleep(1000);
                    }
                    db.Close();
                }
            }
        }

        private static void UpdateDatabaseEntry(string connectionstring, Tree entryvalue)
        {
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");

            string SQL = "update Blocked set LastObserved=@LastObserved, ObservedCount=@ObservedCount where Hostname=@Hostname and IPAddress=@IPAddress";
            Tree values = new Tree();
            values.AddElement("Hostname", entryvalue.GetElement("Hostname"));
            values.AddElement("IPAddress", entryvalue.GetElement("IPAddress"));
            values.AddElement("LastObserved", DateTime.UtcNow.ToString("yyyy-MM-dd"));
            values.AddElement("ObservedCount", entryvalue.GetElement("ObservedCount"));
            db.ExecuteDynamic(SQL, values);
            values.Dispose();
            db.Close();
        }

        private static void InsertDatabaseEntry(string connectionstring, Tree entryvalue, long BlockListId, int recursionDepth)
        {
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");
            Boolean ifIPisNotParsable = false;

            if (entryvalue.GetElement("IPAddress") != null)
            {
                if (entryvalue.GetElement("IPAddress") != "")
                {
                    Boolean isAddressRoutableCIDR = true;
                    switch (entryvalue.GetElement("IPAddress"))
                    {
                        case "0.0.0.0":
                        case "172.16.0.0":
                        case "192.168.0.0":
                            isAddressRoutableCIDR = false;
                            Console.Out.WriteLine("Warning: IP Address " + entryvalue.GetElement("IPAddress") + " not routable CIDR, cannot geolocate hostname '" + entryvalue.GetElement("Hostname") + "' .");
                            break;
                    }

                    if (isAddressRoutableCIDR)
                    {
                        try
                        {
                            geolocate_ip(connectionstring, IPAddress.Parse(entryvalue.GetElement("IPAddress")), entryvalue);
                            arin_lookup(connectionstring, IPAddress.Parse(entryvalue.GetElement("IPAddress")), entryvalue);
                        }
                        catch (Exception ex)
                        {
                            ifIPisNotParsable = true;
                            Console.Out.WriteLine("Warning: IP Address " + entryvalue.GetElement("IPAddress") + " did not parse, entry dropped.");
                        }
                    }
                }
            }

            string ipAddressString = entryvalue.GetElement("IPAddress").Trim();
            string hostnameString = entryvalue.GetElement("Hostname").Trim();

            Boolean process = true;
            if (hostnameString == "" && ipAddressString == "")
            {
                process = false;
            }

            if (hostnameString == "" && ifIPisNotParsable)
            {
                process = false;
            }

            if (process)
            {

                try
                {
                    IPAddress ipAddress = IPAddress.Parse(ipAddressString);
                    if (ipAddress != null)
                    {
                        string hostname = reverseDNS(ipAddress);
                        if (hostname != null)
                        {
                            entryvalue.SetElement("ReverseDNS", hostname);

                            if (hostnameString == "")
                            {
                                entryvalue.SetElement("Hostname", hostname.Trim());
                                hostnameString = hostname.Trim();
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // No reverse dns available
                }

                Boolean saveEntry = true;

                if (hostnameString != "")
                {
                    if (recursionDepth == 1)
                    {
                        tld_country_lookup(connectionstring, entryvalue);
                        if (expandhostname(connectionstring, BlockListId, entryvalue))
                        {
                            entryvalue.SetElement("Resolvable", "1");
                            saveEntry = false; // We would have already completed all these tasks at this point including saving this entry
                        }
                        else
                        {
                            entryvalue.SetElement("Resolvable", "0");
                        }
                    }
                    else
                    {
                        entryvalue.SetElement("Resolvable", "1");
                    }
                }

                if (saveEntry)
                {
                    string SQL = "insert into Blocked (Hostname, IPAddress, CreatedOn, LastObserved, ObservedCount, Latitude, Longitude, AccuracyRadius, Continent, Country, CountryName, Subdivision1, Subdivision2, City, TimeZone, Network, ReverseDNS, ASN, ASO, Resolvable, TLDCountry) OUTPUT Inserted.ID values (@Hostname, @IPAddress, @CreatedOn, @LastObserved, @ObservedCount, @Latitude, @Longitude, @AccuracyRadius, @Continent, @Country, @CountryName, @Subdivision1, @Subdivision2, @City, @TimeZone, @Network, @ReverseDNS, @ASN, @ASO, @Resolvable, @TLDCountry)";
                    Tree values = new Tree();
                    values.AddElement("Hostname", entryvalue.GetElement("Hostname"));
                    if (entryvalue.GetElement("IPAddress") != "0.0.0.0")
                    {
                        values.AddElement("IPAddress", entryvalue.GetElement("IPAddress"));
                    }
                    else
                    {
                        values.AddElement("IPAddress", "");
                    }
                    values.AddElement("CreatedOn", DateTime.UtcNow.ToString("yyyy-MM-dd"));
                    values.AddElement("LastObserved", DateTime.UtcNow.ToString("yyyy-MM-dd"));
                    values.AddElement("ObservedCount", "1");
                    values.AddElement("Latitude", entryvalue.GetElement("Latitude") == null ? "" : entryvalue.GetElement("Latitude"));
                    values.AddElement("Longitude", entryvalue.GetElement("Longitude") == null ? "" : entryvalue.GetElement("Longitude"));
                    values.AddElement("AccuracyRadius", entryvalue.GetElement("AccuracyRadius") == null ? "" : entryvalue.GetElement("AccuracyRadius"));
                    values.AddElement("Continent", entryvalue.GetElement("Continent") == null ? "" : entryvalue.GetElement("Continent"));
                    values.AddElement("Country", entryvalue.GetElement("Country") == null ? "" : entryvalue.GetElement("Country"));
                    values.AddElement("CountryName", entryvalue.GetElement("CountryName") == null ? "" : entryvalue.GetElement("CountryName"));
                    values.AddElement("Subdivision1", entryvalue.GetElement("Subdivision1") == null ? "" : entryvalue.GetElement("Subdivision1"));
                    values.AddElement("Subdivision2", entryvalue.GetElement("Subdivision2") == null ? "" : entryvalue.GetElement("Subdivision2"));
                    values.AddElement("City", entryvalue.GetElement("City") == null ? "" : entryvalue.GetElement("City"));
                    values.AddElement("TimeZone", entryvalue.GetElement("TimeZone") == null ? "" : entryvalue.GetElement("TimeZone"));
                    values.AddElement("Network", entryvalue.GetElement("Network") == null ? "" : entryvalue.GetElement("Network"));
                    values.AddElement("ReverseDNS", entryvalue.GetElement("ReverseDNS") == null ? "" : entryvalue.GetElement("ReverseDNS"));
                    values.AddElement("ASN", entryvalue.GetElement("ASN") == null ? "" : entryvalue.GetElement("ASN"));
                    values.AddElement("ASO", entryvalue.GetElement("ASO") == null ? "" : entryvalue.GetElement("ASO"));
                    values.AddElement("Resolvable", entryvalue.GetElement("Resolvable") == null ? "1" : entryvalue.GetElement("Resolvable"));
                    values.AddElement("TLDCountry", entryvalue.GetElement("TLDCountry") == null ? "Ambiguous" : entryvalue.GetElement("TLDCountry"));

                    DataTable dt = db.ExecuteDynamic(SQL, values);
                    long BlockedId = -1;

                    if (dt != null)
                    {
                        if (dt.Rows.Count > 0)
                        {
                            BlockedId = Convert.ToInt64(dt.Rows[0]["Id"]);
                        }
                    }
                    CheckForExistingEntryAssociation(connectionstring, BlockedId, BlockListId);
                    values.Dispose();
                }

                db.Close();
            }
        }

        private static Boolean CheckForExistingEntry(string connectionstring, Tree entryvalue)
        {
            Boolean result = false;
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");
            string SQL = "select * from Blocked where hostname = @Hostname and ipaddress = @IPAddress";
            Tree values = new Tree();
            values.AddElement("Hostname", entryvalue.GetElement("Hostname"));
            values.AddElement("IPAddress", entryvalue.GetElement("IPAddress"));
            DataTable dt = db.ExecuteDynamic(SQL, values);
            values.Dispose();

            if (dt != null)
            {
                if (dt.Rows.Count > 0)
                {
                    // located
                    result = true;
                    if (dt.Rows[0]["ObservedCount"] != null || dt.Rows[0]["ObservedCount"] != DBNull.Value)
                    {
                        long occurances = 0;
                        try
                        {
                            occurances = Convert.ToInt64(dt.Rows[0]["ObservedCount"]);
                        }
                        catch (Exception)
                        {

                        }
                        occurances++;
                        entryvalue.SetElement("ObservedCount", occurances.ToString());
                    }
                }
            }
            db.Close();
            return result;
        }

        public static Tree readHashCommentedList(string filename)
        {
            Tree result = new Tree();
            int index = 1;

            foreach (string line in System.IO.File.ReadLines(filename))
            {
                string updated = line;
                int hash = updated.IndexOf("#");
                if (hash != -1)
                {
                    updated = updated.Substring(0, hash);
                }

                updated = updated.Trim();
                if (updated.Length > 0)
                {
                    switch (updated)
                    {
                        case "0.0.0.0/8":
                        case "172.16.0.0/12":
                        case "192.168.0.0/16":
                            break;
                        default:
                            if (updated.IndexOf(" ") < 0) // Ignore if name or ip address has a space in the line, it's probably some other type of comment
                            {
                                if (updated.IndexOf("/") > 0)  // Let's assume this is an address range
                                {
                                    Tree newEntry = new Tree();
                                    IPAddress tmpIPAddress = null;

                                    if (IPAddress.TryParse(updated, out tmpIPAddress))
                                    {
                                        newEntry.AddElement("IPAddress", updated);
                                        newEntry.AddElement("Hostname", "");
                                    }

                                    result.AddNode(newEntry, "row");
                                    index++;
                                }
                                else
                                {
                                    Tree newEntry = new Tree();
                                    IPAddress tmpIPAddress = null;

                                    if (IPAddress.TryParse(updated, out tmpIPAddress))
                                    {
                                        newEntry.AddElement("IPAddress", updated);
                                        newEntry.AddElement("Hostname", "");
                                    }
                                    else
                                    {
                                        newEntry.AddElement("Hostname", updated);
                                        newEntry.AddElement("IPAddress", "");
                                    }

                                    result.AddNode(newEntry, "row");
                                    index++;
                                }
                            }
                            break;
                    }
                }
            }

            return result;
        }

        public static Tree readHashCommentedIPandHostList(string filename)
        {
            Tree result = new Tree();
            int index = 1;

            foreach (string line in System.IO.File.ReadLines(filename))
            {
                string updated = line;
                int hash = updated.IndexOf("#");
                if (hash != -1)
                {
                    updated = updated.Substring(0, hash);
                }

                updated = updated.Trim();
                if (updated.Length > 3)
                {
                    string[] split = updated.Split(' ', '\t');
                    if (split.Length == 2)
                    {
                        Tree newEntry = new Tree();
                        newEntry.AddElement("IPAddress", split[0]);
                        newEntry.AddElement("Hostname", split[1]);
                        result.AddNode(newEntry, "row");
                        index++;
                    }
                }
            }
            return result;
        }

        private static void UpdateBlockedListEntry(string connectionstring, string PreviousHash, long? PreviousLength, long? PreviousCount, long ID)
        {
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");

            string SQL = "update Blocklists set PreviousHash=@PreviousHash, PreviousLength=@PreviousLength, PreviousCount=@PreviousCount where ID=@ID";
            Tree values = new Tree();
            values.AddElement("PreviousHash", PreviousHash == null ? "" : PreviousHash);
            values.AddElement("PreviousLength", PreviousLength == null ? "" : PreviousLength.Value.ToString());
            values.AddElement("PreviousCount", PreviousCount == null ? "" : PreviousCount.Value.ToString());
            values.AddElement("ID", ID.ToString());
            db.ExecuteDynamic(SQL, values);
            values.Dispose();
            db.Close();
        }

        private static void InsertDatabaseEntryAssociation(string connectionstring, long blockedid, long blockedlistid)
        {
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");

            string SQL = "insert into BlockedAssociations (BlockedId, BlockedListId) values (@BlockedId, @BlockedListId)";
            Tree values = new Tree();
            values.AddElement("BlockedId", blockedid.ToString());
            values.AddElement("BlockedListId", blockedlistid.ToString());
            db.ExecuteDynamic(SQL, values);
            values.Dispose();
            db.Close();
        }

        private static void CheckForExistingEntryAssociation(string connectionstring, long blockedid, long blockedlistid)
        {
            IntDatabase db = new ADOConnector(connectionstring, "Archlake");

            string SQL = "select * from BlockedAssociations where BlockedId = @BlockedId and BlockedListId = @BlockedListId";
            Tree values = new Tree();
            values.AddElement("BlockedId", blockedid.ToString());
            values.AddElement("BlockedListId", blockedlistid.ToString());
            DataTable dt = db.ExecuteDynamic(SQL, values);
            values.Dispose();

            if (dt != null)
            {
                if (dt.Rows.Count == 0)
                {
                    InsertDatabaseEntryAssociation(connectionstring, blockedid, blockedlistid);
                }
            }
            else
            {
                InsertDatabaseEntryAssociation(connectionstring, blockedid, blockedlistid);
            }
            db.Close();
        }

        private static Boolean expandhostname(string connectionstring, long blockedlistid, Tree entryvalue)
        {
            Boolean resolvable = false;

            string hostname = entryvalue.GetElement("Hostname");
            IPAddress[] allIPsResolved = resolveHostname(hostname);
            if (allIPsResolved != null)
            {
                foreach (IPAddress currentIP in allIPsResolved)
                {
                    resolvable = true;
                    Tree entry = entryvalue.Duplicate();
                    entry.SetElement("IPAddress", currentIP.ToString());
                    ProcessBlockedEntry(connectionstring, entry, blockedlistid, 2).Wait();
                    entry.Dispose();
                }
            }
            return resolvable;
        }

        private static IPAddress[] resolveHostname(string hostname)
        {
            try
            {
                IPHostEntry resolved = Dns.GetHostEntry(hostname);
                if (resolved != null)
                {
                    return resolved.AddressList;
                }
            }
            catch (Exception)
            {

            }
            
            return null;
        }

        private static string reverseDNS(IPAddress address)
        {
            try
            {
                IPHostEntry resolved = Dns.GetHostEntry(address);
                if (resolved != null)
                {
                    return resolved.HostName;
                }
            }
            catch (Exception)
            {

            }
            
            return null;
        }

        private static void geolocate_ip(string connectionstring, IPAddress ipaddress, Tree entry)
        {
            string networkrange = "";
            if (ipaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                Boolean rangecrawl = true;
                int stage = 0;
                string netmask = "255.255.255.0";

                while (rangecrawl)
                {
                    string postfix = "/24";
                    switch (stage)
                    {
                        case 0:
                            postfix = "/24";
                            netmask = "255.255.255.0";
                            break;
                        case 1:
                            postfix = "/23";
                            netmask = "255.255.254.0";
                            break;
                        case 2:
                            postfix = "/22";
                            netmask = "255.255.252.0";
                            break;
                        case 3:
                            postfix = "/21";
                            netmask = "255.255.248.0";
                            break;
                        case 4:
                            postfix = "/20";
                            netmask = "255.255.240.0";
                            break;
                        case 5:
                            postfix = "/19";
                            netmask = "255.255.224.0";
                            break;
                        case 6:
                            postfix = "/18";
                            netmask = "255.255.192.0";
                            break;
                        case 7:
                            postfix = "/17";
                            netmask = "255.255.128.0";
                            break;
                        case 8:
                            postfix = "/16";
                            netmask = "255.255.0.0";
                            break;
                        case 9:
                            postfix = "/15";
                            netmask = "255.254.0.0";
                            break;
                        case 10:
                            postfix = "/14";
                            netmask = "255.252.0.0";
                            break;
                        case 11:
                            postfix = "/13";
                            netmask = "255.248.0.0";
                            break;
                        case 12:
                            postfix = "/12";
                            netmask = "255.240.0.0";
                            break;
                        case 13:
                            postfix = "/11";
                            netmask = "255.224.0.0";
                            break;
                        case 14:
                            postfix = "/10";
                            netmask = "255.192.0.0";
                            break;
                        case 15:
                            postfix = "/9";
                            netmask = "255.128.0.0";
                            break;
                        case 16:
                            postfix = "/8";
                            netmask = "255.0.0.0";
                            break;
                        default:
                            rangecrawl = false;
                            break;
                    }

                    // Calculate Netmask
                    IPAddress ipnetmask = IPAddress.Parse(netmask);
                    IPNetwork ipnetwork = IPNetwork.Parse(ipaddress, ipnetmask);
                    networkrange = ipnetwork.Network.ToString() + postfix;

                    if (networkrange != "")
                    {
                        IntDatabase db = new ADOConnector(connectionstring, "World");

                        string SQL = @"SELECT [latitude], [longitude], [accuracy_radius], [continent_name], [country_iso_code], 
                                  [country_name], [subdivision_1_name], [subdivision_2_name], [city_name], [time_zone]
                           FROM [World].[dbo].[GeoLite2-City-Blocks-IPv4]
                           join [geolite2-city-locations-en] on [GeoLite2-City-Blocks-IPv4].geoname_id=[geolite2-city-locations-en].geoname_id
                           where [GeoLite2-City-Blocks-IPv4].network = @ipquery";

                        Tree values = new Tree();
                        values.AddElement("@ipquery", networkrange);
                        DataTable dt = db.ExecuteDynamic(SQL, values);
                        values.Dispose();

                        if (dt.Rows.Count > 0)
                        {
                            rangecrawl = false;
                            if (dt.Rows.Count > 1)
                            {
                                Console.Out.WriteLine("Warning:  more than one network matches, picking first on list.");
                            }

                            entry.SetElement("Latitude", dt.Rows[0]["latitude"].ToString());
                            entry.SetElement("Longitude", dt.Rows[0]["longitude"].ToString());
                            entry.SetElement("AccuracyRadius", dt.Rows[0]["accuracy_radius"].ToString());
                            entry.SetElement("Continent", dt.Rows[0]["continent_name"].ToString());
                            entry.SetElement("Country", dt.Rows[0]["country_iso_code"].ToString());
                            entry.SetElement("CountryName", dt.Rows[0]["country_name"].ToString());
                            entry.SetElement("Subdivision1", dt.Rows[0]["subdivision_1_name"].ToString());
                            entry.SetElement("Subdivision2", dt.Rows[0]["subdivision_2_name"].ToString());
                            entry.SetElement("City", dt.Rows[0]["city_name"].ToString());
                            entry.SetElement("TimeZone", dt.Rows[0]["time_zone"].ToString());
                        }
                        else
                        {
                            stage++;
                        }
                        db.Close();
                    }
                }
            }
            else
            {
                // Handle v6 here...
            }
        }

        private static Boolean isBlockedEntryValid(Tree entry)
        {
            Boolean isvalid = false;

            string ipaddress = entry.GetElement("IPAddress");
            string hostname = entry.GetElement("Hostname");

            if (ipaddress != null && ipaddress != "" && ipaddress != "0.0.0.0" && ipaddress != "0.0.0.0/0")
            {
                isvalid = true;
            }

            if (hostname != null && hostname != "")
            {
                isvalid = true;
            }

            return isvalid;
        }

        private static void arin_lookup(string connectionstring, IPAddress ipaddress, Tree entry)
        {
            string networkrange = "";
            if (ipaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                Boolean rangecrawl = true;
                int stage = 0;
                string netmask = "255.255.255.0";

                while (rangecrawl)
                {
                    string postfix = "/24";
                    switch (stage)
                    {
                        case 0:
                            postfix = "/24";
                            netmask = "255.255.255.0";
                            break;
                        case 1:
                            postfix = "/23";
                            netmask = "255.255.254.0";
                            break;
                        case 2:
                            postfix = "/22";
                            netmask = "255.255.252.0";
                            break;
                        case 3:
                            postfix = "/21";
                            netmask = "255.255.248.0";
                            break;
                        case 4:
                            postfix = "/20";
                            netmask = "255.255.240.0";
                            break;
                        case 5:
                            postfix = "/19";
                            netmask = "255.255.224.0";
                            break;
                        case 6:
                            postfix = "/18";
                            netmask = "255.255.192.0";
                            break;
                        case 7:
                            postfix = "/17";
                            netmask = "255.255.128.0";
                            break;
                        case 8:
                            postfix = "/16";
                            netmask = "255.255.0.0";
                            break;
                        case 9:
                            postfix = "/15";
                            netmask = "255.254.0.0";
                            break;
                        case 10:
                            postfix = "/14";
                            netmask = "255.252.0.0";
                            break;
                        case 11:
                            postfix = "/13";
                            netmask = "255.248.0.0";
                            break;
                        case 12:
                            postfix = "/12";
                            netmask = "255.240.0.0";
                            break;
                        case 13:
                            postfix = "/11";
                            netmask = "255.224.0.0";
                            break;
                        case 14:
                            postfix = "/10";
                            netmask = "255.192.0.0";
                            break;
                        case 15:
                            postfix = "/9";
                            netmask = "255.128.0.0";
                            break;
                        case 16:
                            postfix = "/8";
                            netmask = "255.0.0.0";
                            break;
                        default:
                            rangecrawl = false;
                            break;
                    }
                    // Calculate Netmask
                    IPAddress ipnetmask = IPAddress.Parse(netmask);
                    IPNetwork ipnetwork = IPNetwork.Parse(ipaddress, ipnetmask);
                    networkrange = ipnetwork.Network.ToString() + postfix;

                    if (networkrange != "")
                    {
                        IntDatabase db = new ADOConnector(connectionstring, "World");

                        string SQL = @"SELECT [autonomous_system_number], [autonomous_system_organization]
                           FROM [World].[dbo].[GeoLite2-ASN-Blocks-IPv4]
                           where network = @ipquery";

                        Tree values = new Tree();
                        values.AddElement("@ipquery", networkrange);
                        DataTable dt = db.ExecuteDynamic(SQL, values);
                        values.Dispose();

                        if (dt.Rows.Count > 0)
                        {
                            rangecrawl = false;
                            if (dt.Rows.Count > 1)
                            {
                                Console.Out.WriteLine("Warning:  more than one network matches, picking first on list.");
                            }

                            entry.SetElement("Network", networkrange);
                            entry.SetElement("ASN", dt.Rows[0]["autonomous_system_number"].ToString());
                            entry.SetElement("ASO", dt.Rows[0]["autonomous_system_organization"].ToString());
                        }
                        else
                        {
                            stage++;
                        }
                        db.Close();
                    }
                }
            }
            else
            {
                // Handle v6 here...
            }
        }

        private static void tld_country_lookup(string connectionstring, Tree entry)
        {
            if (entry.GetElement("Hostname")!=null)
            {
                if (entry.GetElement("Hostname").Trim()!="")
                {
                    string[] segments = entry.GetElement("Hostname").Trim().Split('.');
                    if (segments.Length>1)
                    {
                        int tldindex = segments.Length - 1;
                        string tld = segments[tldindex];

                        IntDatabase db = new ADOConnector(connectionstring, "World");
                        string SQL = @"SELECT [country] FROM [World].[dbo].[country-codes-tlds] where tld = @tld";

                        Tree values = new Tree();
                        values.AddElement("@tld", "." + tld);
                        DataTable dt = db.ExecuteDynamic(SQL, values);
                        values.Dispose();

                        if (dt.Rows.Count > 0)
                        {
                            entry.SetElement("TLDCountry", dt.Rows[0]["country"].ToString());
                        }
                        db.Close();
                    }
                }
            }
        }
    }
}
