/*
Package volume manages the persistent storage that backs Blimp volumes.

BACKGROUND

Each namespace has a single PersistentVolume. This volume persists across
`blimp down`s, and is only deleted when `blimp down --volumes` is run.

This PersistentVolume contains all the user-defined volumes (both regular
volumes, and bind volumes) as subdirectories. Using a single PersistentVolume
(rather than a PersistentVolume per user volume) is required to work around
limits on the number of PersistentVolumes that can be bound to a single Node.

VOLUME CREATION

Blimp doesn't create PersistentVolumes directly. The PersistentVolume for each
namespace is created by using a PersistentVolumeClaim with an empty storage
class. The Kubernetes cluster's default PersistentVolume provisioner then
dynamically creates the volume.

After the PersistentVolume is created, Blimp labels the PersistentVolume so
that it's uniquely attached to the user's namespace. Any subsequent `blimp up`s
then always use this PersistentVolume.

The user's PersistentVolume is referenced by pods via a PersistentVolumeClaim
in the user's namespace. When the user's namespace is created, a
PersistentVolumeClaim is deployed that explicitly references the user's
PersistentVolume. Pods then mount the PersistentVolumeClaim.

PERSISTING ACROSS `blimp down`s

Because PVC objects are namespaced, deleting the user's namespace during `blimp
down` also deletes the PVC. Therefore, we ensure that the user's
PersistentVolume has a reclaim policy of Retain. The default policy of Delete
would cause Kubernetes to automatically delete the PersistentVolume when the
PVC is deleted.

Once a PVC associated with a Retained PersistentVolume is deleted, the
PersistentVolume enters the VolumeReleased phase. This phase is intended for
cluster administrators to wipe the volume, before allowing new PVCs to bind to
it. In our case, we don't need to change the contents of the PersistentVolume
-- we want the contents to stay the same until the next `blimp up`.

Each time we initialize the PVC, we make sure the PersistentVolume is Available
by unsetting all claims if the volume is Released. There should never be a case
where a new PVC is created while another PVC is bound to the namespace's
PersistentVolume.

VOLUME DELETION

Permanently deleting a PersistentVolume is done by setting the PersistentVolume's
reclaim policy to Delete. When the claim associated with the PersistentVolume
is deleted, the PersistentVolume controller will automatically delete the
PersistentVolume according to the Delete reclaim policy.

Note that this controller _is not_ a Blimp component. It's just part of the
abstraction Kubernetes provides for PersistentVolumes.
*/
package volume
