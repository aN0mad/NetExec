#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from impacket.ldap import ldapasn1 as ldapasn1_impacket


class NXCModule:

    name = 'domain-level'
    description = "Retrieve the functional domain level using the msDS-Behavior-Version attribute."
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d7422d35-448a-451a-8846-6a7def0044df?redirectedfrom=MSDN
    FUNCTIONAL_LEVEL = {
        "0": "DS_BEHAVIOR_WIN2000",
        "1": "DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS",
        "2": "DS_BEHAVIOR_WIN2003",
        "3": "DS_BEHAVIOR_WIN2008",
        "4": "DS_BEHAVIOR_WIN2008R2",
        "5": "DS_BEHAVIOR_WIN2012",
        "6": "DS_BEHAVIOR_WIN2012R2",
        "7": "DS_BEHAVIOR_WIN2016",
    }

    def options(self, context, module_options):
        '''
        '''
        pass

    # format the functional level of the domain
    def formatFunctionalLevel(self, behavior_version):
        # Taken from bloodyAD:
        # https://github.com/CravateRouge/bloodyAD/blob/265466b9c2d05bb20c2944448eade40a323b6fdd/bloodyAD/formatters/formatters.py#L49
        return (
            self.FUNCTIONAL_LEVEL[behavior_version]
            if behavior_version in self.FUNCTIONAL_LEVEL
            else behavior_version
        )

    def on_login(self, context, connection):
        msds_behavior_version = None

        # Define search filter and retrieve the msDS-Behavior-Version attribute
        attributes = ['msDS-Behavior-Version']
        search_filter = '(objectClass=domain)'

        context.log.info(f"Using search filter: {search_filter}")
        context.log.info(f"Attributes to retrieve: {attributes}")

        # Execute the search and parse the response
        resp = connection.search(search_filter, attributes)

        if resp:
            context.log.debug(f"Total records returned {len(resp):d}")
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "msDS-Behavior-Version":
                            msds_behavior_version = str(attribute["vals"][0])
                    context.log.success(f"msDS-Behavior-Version (Unformatted): {msds_behavior_version}")
                except Exception as e:
                    context.log.debug("Exception:", exc_info=True)
                    context.log.debug(f"Skipping item, cannot process due to error {e}")

        # Format and display the domain functional level
        if msds_behavior_version is not None:
            context.log.highlight(f"Domain Functional Level (msDS-Behavior-Version): {self.formatFunctionalLevel(msds_behavior_version)}")
        else:
            context.log.error("Failed to retrieve msDS-Behavior-Version.")
