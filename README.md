# Proliferation Threat Intelligence

Summary:  Console application that processes public sources for internet threat intelligence in order to complete the
          missing data.

GIVEN that there are multiple sources for reporting hostile IP addresses and/or domain names
And that additional details would be helpful to determine the nature of the threat that are not provided
THEN this application will provide multiple means to passively identify more details about the threat
such that direct interaction with the attackers and/or Advanced Persistent Threats is not necessary
AND record the missing details in a database that can be used for analysis and reporting.

Requirement 1:  Locate missing IP address when only provided a domain name
Requirement 2:  Identify DNS entries associated with an IP address
Requirement 3:  Use reverse DNS to identify the domain name compared to the IP address, regardless of provided DNS entry
Requirement 4:  Use geolocation database for IP address to identify country of origin
Requirement 5:  After completion of process, repeat every 24 hours.

Primary Use Case:  Detects impersonation.  For example, the Threat Intelligence tool has shown many hostile Ukrainian
                   web sites as serving malware.  However, these were identified only by the means of the DNS entry
                   provided.  After resolving their IP origins, have been detected as being served from Russian ISPs.

Goal:  Over a period of time, it should become obvious which ISPs are supporting Advanced Persistent Threats,
       and a method can be devised to proactively block new threats globally.

Current notes:  This isn't particularly user friendly at the moment and should be considered in ALPHA until
                it gets cleaned up a bit.  It does not currently create the schemas or import the data on its
                own as of this writing, and this comment will be removed and replaced with detailed instructions
                once the code is completed.
