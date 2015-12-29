#ifndef _NET_IF_LAT_H_
#define _NET_IF_LAT_H_

struct lat_softc {
	struct ifnet	lat_if;	   /* common area - must be at the top */
	struct sockaddr	*lat_psrc; /* Physical src addr */
	struct sockaddr	*lat_pdst; /* Physical dst addr */
	LIST_ENTRY(lat_softc) lat_list;	/* list of all lats */
};

#endif /* !_NET_IF_LAT_H_ */
