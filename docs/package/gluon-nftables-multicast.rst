gluon-nftables-multicast
========================

The *gluon-nftables-multicast* package provides the base ruleset that Gluon's
multicast handling is built upon. It does not filter regular payload traffic
itself, but sets up the bridge chains used by packages like
:doc:`gluon-nftables-filter-multicast`, and implements the IGMP/MLD domain
segmentation.

Multicast packets passing between the nodes' client bridge (*br-client*) and
the mesh interface (*bat0*) are directed into a pair of chains: *MULTICAST_IN*
for packets coming from the mesh, and *MULTICAST_OUT* for packets going into
the mesh. ICMPv6 is handled in the separate chains *MULTICAST_IN_ICMPV6* and
*MULTICAST_OUT_ICMPV6*. In addition, the chains *IN_ONLY* and *OUT_ONLY* are
provided, which only pass packets that were received from or are sent to the
mesh interface (*bat0*) or the local port (*local-port*) of the client bridge,
and drop everything else.

On top of these chains, IGMP and MLD queries are dropped in both directions,
so that each node acts as the querier for its own local clients. Unless
disabled in the *site.conf*, membership reports and leave messages are dropped
as well. See :ref:`site.conf mesh section <user-site-mesh>` and
:ref:`igmp-mld-domain-segmentation` for details.

This package is a dependency of *gluon-mesh-batman-adv* and is therefore
installed on all batman-adv based images.
