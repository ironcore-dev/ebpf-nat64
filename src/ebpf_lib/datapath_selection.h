#ifndef DATAPATH_SELECTION_H
#define DATAPATH_SELECTION_H

#ifndef STATELESS_NAT64 // Meson will define this when stateless is false
  #include "nat64_kern.h"
  #include "stateful_datapath_maps.h"
  #include "stateful_datapath_funcs.h"
  #define process_ipv6_pkt stateful_process_ipv6_pkt
  #define process_ipv4_pkt stateful_process_ipv4_pkt
  #define nat64_exporter_increment_translated_pkts nat64_exporter_increment_accepted_flows // Alias for exporter
#else // Stateless mode
  #include "stateless_datapath_maps.h"
  #include "stateless_datapath_funcs.h"
  #define process_ipv6_pkt stateless_process_ipv6_pkt
  #define process_ipv4_pkt stateless_process_ipv4_pkt
  #define nat64_exporter_increment_translated_pkts nat64_exporter_increment_translated_pkts_stateless
#endif

#endif // DATAPATH_SELECTION_H
