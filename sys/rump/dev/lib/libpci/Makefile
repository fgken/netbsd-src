#	$NetBSD: Makefile,v 1.9 2015/11/01 22:41:24 pooka Exp $
#

RUMPTOP= ${TOPRUMP}

.include <bsd.own.mk>

.PATH:	${RUMPTOP}/../dev/pci

LIB=	rumpdev_pci
COMMENT=PCI bus support

IOCONF=	PCI.ioconf

SRCS+=	pci.c pci_map.c pci_quirks.c pci_subr.c pci_stub.c pci_usrreq.c
SRCS+=	pcibusprint.c

SRCS+=	rumpdev_pci.c

# ok, these don't _really_ belong here, but it's the only
# place they're currently useful, so let it slide
SRCS+=	rumpdev_bus_space.c
SRCS+=	rumpdev_bus_dma.c

SRCS+=	pci_at_mainbus.c

CPPFLAGS+= -I${RUMPTOP}/librump/rumpkern
CPPFLAGS+= -I${RUMPTOP}/librump/rumpvfs

.if ${RUMP_PCI_IOSPACE:Uno} == "yes"
.error RUMP_PCI_IOSPACE defined in Makefile.  Use userfeatures.h instead.
.endif

.PATH:			${RUMPCOMP_USER_PATH.rumpdev_pci}
RUMPCOMP_USER_SRCS=	${RUMPCOMP_USER_SRCS.rumpdev_pci}
MYDIR:=			${.PARSEDIR}
RUMPCOMP_USER_CPPFLAGS=	-I${MYDIR}
RUMPCOMP_USER_CPPFLAGS+=${RUMPCOMP_USER_CPPFLAGS.rumpdev_pci}
RUMPCOMP_USER_CFLAGS=	${RUMPCOMP_USER_CFLAGS.rumpdev_pci}

CPPFLAGS+=		${RUMPCOMP_CPPFLAGS.rumpdev_pci}

# XXX: messy
.undef RUMPKERN_ONLY

.ifdef RUMPCOMP_MAKEFILEINC.rumpdev_pci
.warning RUMPCOMP_MAKEFILEINC interface is unstable and may change
.include "${RUMPCOMP_MAKEFILEINC.rumpdev_pci}"
.endif

.include "${RUMPTOP}/Makefile.rump"
.include <bsd.lib.mk>
.include <bsd.klinks.mk>
