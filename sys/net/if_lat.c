#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_lat.c,v 1.00 2015/12/11 Exp $");

#ifdef _KERNEL_OPT
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/cpu.h>
#include <sys/intr.h>
#include <sys/kmem.h>
#include <sys/atomic.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef	INET
#include <netinet/in_var.h>
#endif	/* INET */

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#endif /* INET6 */

#include <netinet/ip_encap.h>
#include <net/if_lat.h>

#include <net/net_osdep.h>

#include "ioconf.h"

/*
 * lat global variable definitions
 */
LIST_HEAD(, lat_softc) lat_softc_list;

static int	lat_clone_create(struct if_clone *, int);
static int	lat_clone_destroy(struct ifnet *);

static struct if_clone lat_cloner =
    IF_CLONE_INITIALIZER("lat", lat_clone_create, lat_clone_destroy);


void
latattach(int count)
{
    printf("lat: Line Aggregation Tunnel is attached\n");

	LIST_INIT(&lat_softc_list);
	if_clone_attach(&lat_cloner);
}

static int
lat_clone_create(struct if_clone *ifc, int unit)
{
	struct lat_softc *sc;

	sc = kmem_zalloc(sizeof(struct lat_softc), KM_SLEEP);
	if (sc == NULL)
		return ENOMEM;

	if_initname(&sc->lat_if, ifc->ifc_name, unit);

	//latattach0(sc);

	LIST_INSERT_HEAD(&lat_softc_list, sc, lat_list);
	return (0);
}

static int
lat_clone_destroy(struct ifnet *ifp)
{
	struct lat_softc *sc = (void *) ifp;

	LIST_REMOVE(sc, lat_list);

	//lat_delete_tunnel(&sc->lat_if);
	//bpf_detach(ifp);
	//if_detach(ifp);
	//rtcache_free(&sc->lat_ro);

	//cv_destroy(&sc->lat_si_cv);
	//mutex_obj_free(sc->lat_si_lock);
	kmem_free(sc, sizeof(struct lat_softc));

	return (0);
}
