/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use core::fmt;

use crate::acl::Accessor;
use crate::data_model::objects::Endpoint;
use crate::error::Error;
use crate::interaction_model::core::{IMStatusCode, ReportDataReq};
use crate::interaction_model::messages::ib::{
    AttrData, AttrPath, AttrStatus, CmdData, CmdStatus, DataVersionFilter,
};
use crate::interaction_model::messages::msg::{InvReqRef, WriteReqRef};
use crate::interaction_model::messages::GenericPath;
use crate::tlv::{TLVArray, TLVElement};

use super::{AttrDetails, Cluster, ClusterId, CmdDetails, EndptId};

/// The main Matter metadata type describing a Matter Node.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    /// The ID of the node.
    pub id: u16,
    /// The endpoints of the node.
    pub endpoints: &'a [Endpoint<'a>],
}

impl<'a> Node<'a> {
    /// Create a new node with the given ID and endpoints.
    pub const fn new(id: u16, endpoints: &'a [Endpoint<'a>]) -> Self {
        Self { id, endpoints }
    }

    /// Expand (potentially wildcard) read requests into concrete attribute details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the attributes are
    /// accessible by the accessor and whether they should be served based on the
    /// fabric filtering and dataver filtering rules and filter out the inaccessible ones (wildcard reads)
    /// or report an error status for the non-wildcard ones.
    pub fn read<'m>(
        &'m self,
        req: &'m ReportDataReq,
        accessor: &'m Accessor<'m>,
    ) -> Result<impl Iterator<Item = Result<Result<AttrDetails, AttrStatus>, Error>> + 'm, Error>
    {
        let fabric_filtered = req.fabric_filtered()?;
        let dataver_filters = req.dataver_filters()?;

        Ok(PathExpander::new(
            self,
            accessor,
            req.attr_requests()?.map(|reqs| {
                reqs.into_iter().map(move |path_result| {
                    path_result.map(|path| AttrReadPath {
                        path,
                        dataver_filters: dataver_filters.clone(),
                        fabric_filtered,
                    })
                })
            }),
        ))
    }

    /// Expand (potentially wildcard) write requests into concrete attribute details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the attributes are
    /// accessible by the accessor and filter out the inaccessible ones (wildcard writes)
    /// or report an error status for the non-wildcard ones.
    pub fn write<'m>(
        &'m self,
        req: &'m WriteReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(AttrDetails, TLVElement<'m>), AttrStatus>, Error>> + 'm,
        Error,
    > {
        Ok(PathExpander::new(
            self,
            accessor,
            Some(req.write_requests()?.into_iter()),
        ))
    }

    /// Expand (potentially wildcard) invoke requests into concrete command details
    /// using the node metadata.
    ///
    /// As part of the expansion, the method will check whether the commands are
    /// accessible by the accessor and filter out the inaccessible ones (wildcard invocations)
    /// or report an error status for the non-wildcard ones.
    #[inline(never)]
    pub fn invoke<'m>(
        &'m self,
        req: &'m InvReqRef,
        accessor: &'m Accessor<'m>,
    ) -> Result<
        impl Iterator<Item = Result<Result<(CmdDetails, TLVElement<'m>), CmdStatus>, Error>> + 'm,
        Error,
    > {
        Ok(PathExpander::new(
            self,
            accessor,
            req.inv_requests()?.map(move |reqs| reqs.into_iter()),
        ))
    }
}

impl<'a> core::fmt::Display for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            writeln!(f, "endpoint {}: {}", index, endpoint)?;
        }

        write!(f, "")
    }
}

/// A dynamic node that can be modified at runtime.
pub struct DynamicNode<'a, const N: usize> {
    id: u16,
    endpoints: heapless::Vec<Endpoint<'a>, N>,
}

impl<'a, const N: usize> DynamicNode<'a, N> {
    /// Create a new dynamic node with the given ID.
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            endpoints: heapless::Vec::new(),
        }
    }

    /// Return a static node view of the dynamic node.
    ///
    /// Nercessary, because the `Metadata` trait needs a `Node` type
    pub fn node(&self) -> Node<'_> {
        Node {
            id: self.id,
            endpoints: &self.endpoints,
        }
    }

    /// Add an endpoint to the dynamic node.
    pub fn add(&mut self, endpoint: Endpoint<'a>) -> Result<(), Endpoint<'a>> {
        if !self.endpoints.iter().any(|ep| ep.id == endpoint.id) {
            self.endpoints.push(endpoint)
        } else {
            Err(endpoint)
        }
    }

    /// Remove an endpoint from the dynamic node.
    pub fn remove(&mut self, endpoint_id: u16) -> Option<Endpoint<'a>> {
        let index = self
            .endpoints
            .iter()
            .enumerate()
            .find_map(|(index, ep)| (ep.id == endpoint_id).then_some(index));

        if let Some(index) = index {
            Some(self.endpoints.swap_remove(index))
        } else {
            None
        }
    }
}

impl<'a, const N: usize> core::fmt::Display for DynamicNode<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node().fmt(f)
    }
}

/// A helper type for `AttrPath` that enriches it with the request-scope information
/// of whether the attributes served as part of that request should be fabric filtered
/// as well as with information which attributes should only be served if their
/// dataver had changed.
#[derive(Debug)]
struct AttrReadPath<'a> {
    path: AttrPath,
    dataver_filters: Option<TLVArray<'a, DataVersionFilter>>,
    fabric_filtered: bool,
}

/// A helper type for `PathExpander` that captures what type of expansion is being done:
/// Read requests, write requests, or invoke requests.
#[derive(Debug)]
enum LeafAccess {
    AttrRead,
    AttrWrite,
    Command,
}

/// A helper trait type for `PathExpander` modeling a generic "item which can be expanded".
///
/// The item must contain a path (`GenericPath`) but might contain other data as well,
/// which needs to be carried over to the expanded output.
trait PathExpansionItem<'a> {
    /// Leaf type (attr for reading, attr for writing, command)
    const LEAF_ACCESS: LeafAccess;

    /// The type of the expanded item
    type Expanded<'n>;
    /// The type of the error status if expansion of that particular item failed
    type Status;

    /// The path of the item to be expanded
    fn path(&self) -> GenericPath;

    /// Expand the item into the expanded output.
    ///
    /// When expanding, the provided endpoint/cluser/leaf IDs are used
    /// as the original ones might be wildcarded.
    fn expand(
        &self,
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error>;

    /// Convert the item into an error status if the expansion failed.
    fn into_status(self, status: IMStatusCode) -> Self::Status;
}

/// `PathExpansionItem` implementation for `AttrReadPath` (attr read requests expansion).
impl<'a> PathExpansionItem<'a> for AttrReadPath<'a> {
    const LEAF_ACCESS: LeafAccess = LeafAccess::AttrRead;

    type Expanded<'n> = AttrDetails<'n>;
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        Ok(AttrDetails {
            node,
            endpoint_id,
            cluster_id,
            attr_id: leaf_id as _,
            wildcard: self.path.to_gp().is_wildcard(),
            list_index: self.path.list_index,
            fab_idx: accessor.fab_idx,
            fab_filter: self.fabric_filtered,
            dataver: dataver(self.dataver_filters.as_ref(), endpoint_id, cluster_id)?,
        })
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(&self.path.to_gp(), status, 0)
    }
}

/// `PathExpansionItem` implementation for `AttrData` (attr write requests expansion).
impl<'a> PathExpansionItem<'a> for AttrData<'a> {
    const LEAF_ACCESS: LeafAccess = LeafAccess::AttrWrite;

    type Expanded<'n> = (AttrDetails<'n>, TLVElement<'n>);
    type Status = AttrStatus;

    fn path(&self) -> GenericPath {
        self.path.to_gp()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            AttrDetails {
                node,
                endpoint_id,
                cluster_id,
                attr_id: leaf_id as _,
                wildcard: self.path.to_gp().is_wildcard(),
                list_index: self.path.list_index,
                fab_idx: accessor.fab_idx,
                fab_filter: false,
                dataver: self.data_ver,
            },
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        AttrStatus::new(&self.path.to_gp(), status, 0)
    }
}

/// `PathExpansionItem` implementation for `CmdData` (command requests expansion).
impl<'a> PathExpansionItem<'a> for CmdData<'a> {
    const LEAF_ACCESS: LeafAccess = LeafAccess::Command;

    type Expanded<'n> = (CmdDetails<'n>, TLVElement<'n>);
    type Status = CmdStatus;

    fn path(&self) -> GenericPath {
        self.path.path.clone()
    }

    fn expand(
        &self,
        node: &'a Node<'a>,
        _accessor: &'a Accessor<'a>,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        leaf_id: u32,
    ) -> Result<Self::Expanded<'a>, Error> {
        let expanded = (
            CmdDetails {
                node,
                endpoint_id,
                cluster_id,
                cmd_id: leaf_id,
                wildcard: false,
            },
            self.data.clone(),
        );

        Ok(expanded)
    }

    fn into_status(self, status: IMStatusCode) -> Self::Status {
        CmdStatus::new(self.path, status, 0)
    }
}

/// An iterator that expands a list of paths into concrete attribute/command details.
///
/// While the iterator can be (and used to be) implemented by using monadic combinators,
/// this implementation is done in a more imperative way to avoid the overhead of monadic
/// combinators in terms of memory size.
struct PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
{
    /// The metatdata node to expand the paths on.
    node: &'a Node<'a>,
    /// The accessor to check the access rights.
    accessor: &'a Accessor<'a>,
    /// The paths to expand.
    items: Option<I>,
    /// The current path item being expanded.
    item: Option<T>,
    /// The current endpoint index.
    /// Might not yet be computed (UNKNOWN_INDEX).
    endpoint_index: usize,
    /// The current cluster index.
    /// Might not yet be computed (UNKNOWN_INDEX).
    cluster_index: usize,
    /// The current leaf index.
    /// Might not yet be computed (UNKNOWN_INDEX).
    leaf_index: usize,
}

impl<'a, T, I> PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
{
    /// The index value for an unknown index.
    /// Used instead of `Option<usize>` to save memory.
    /// (`Option<usize>` would be 2 words due to memory alignment, `usize` is 1 word)
    const UNKNOWN_INDEX: usize = usize::MAX;

    /// Create a new path expander with the given node, accessor, and paths.
    pub const fn new(node: &'a Node<'a>, accessor: &'a Accessor<'a>, paths: Option<I>) -> Self {
        Self {
            node,
            accessor,
            items: paths,
            item: None,
            endpoint_index: Self::UNKNOWN_INDEX,
            cluster_index: Self::UNKNOWN_INDEX,
            leaf_index: Self::UNKNOWN_INDEX,
        }
    }

    /// Move to the next endpoint in the path.
    fn next_endpoint(&mut self) -> bool {
        let Some(path) = self.item.as_ref().map(PathExpansionItem::path) else {
            // No item to expand. Indicate to the main iterator that it needs to fetch the next one
            return false;
        };

        if self.endpoint_index == Self::UNKNOWN_INDEX {
            // The index of the expanded endpoint is not yet known. Compute it.

            if let Some(endpoint) = path.endpoint {
                // Non-wildcard endpoint case

                let Some(endpoint_index) =
                    self.node.endpoints.iter().position(|ep| ep.id == endpoint)
                else {
                    // This endpoint does not exist in our meta-data
                    // bail-out with `false`

                    return false;
                };

                self.endpoint_index = endpoint_index;
            } else if self.node.endpoints.is_empty() {
                // No endpoints in the node and the path is a wildcard one
                return false;
            } else {
                // Position on the first endpoint for a wildcard traversal
                self.endpoint_index = 0;
            }
        } else if path.endpoint.is_some() || self.endpoint_index == self.node.endpoints.len() - 1 {
            // Cannot move to the next endpoint
            // Bail out with `false` and indicate to the main iterator that it needs to fetch the next item
            return false;
        }

        // Move to the next endpoint for a wildcard traversal
        self.endpoint_index += 1;
        true
    }

    /// Move to the next cluster in the path and if the clusters of the current endpoint are exhausted,
    /// move to the next endpoint.
    fn next_cluster(&mut self) -> bool {
        loop {
            let Some(path) = self.item.as_ref().map(PathExpansionItem::path) else {
                // No item to expand. Indicate to the main iterator that it needs to fetch the next one
                return false;
            };

            if self.cluster_index == Self::UNKNOWN_INDEX {
                // The index of the expanded cluster is not yet known. Compute it.

                // Make sure we have a valid endpoint position first
                if !self.next_endpoint() {
                    break false;
                }

                if let Some(cluster) = path.cluster {
                    // Non-wildcard cluster case

                    let Some(cluster_index) = self.node.endpoints[self.endpoint_index]
                        .clusters
                        .iter()
                        .position(|cl| cl.id == cluster)
                    else {
                        // This cluster does not exist in our meta-data.
                        // Try to move to the next endpoint
                        continue;
                    };

                    self.cluster_index = cluster_index;
                } else if self.node.endpoints[self.endpoint_index].clusters.is_empty() {
                    // No clusters in the current endpoint and the path is a wildcard one, move to the next endpoint
                    continue;
                } else {
                    // Position on the first cluster for a wildcard traversal
                    self.cluster_index = 0;
                }

                break true;
            }

            if path.cluster.is_some()
                || self.cluster_index == self.node.endpoints[self.endpoint_index].clusters.len() - 1
            {
                // Cannot move to the next cluster as the clusters of the current endpoint are exchausted
                // or the cluster is a non-wildcard one.
                // Try to move to the next endpoint
                self.cluster_index = Self::UNKNOWN_INDEX;
                continue;
            }

            // Move to the next cluster for a wildcard traversal
            self.cluster_index += 1;
            break true;
        }
    }

    /// Move to the next leaf in the path and if the leaves of the current cluster are exhausted,
    /// move to the next cluster and so on to the next endpoint, if necessary.
    fn next_leaf(&mut self) -> bool {
        let command = matches!(T::LEAF_ACCESS, LeafAccess::Command);

        loop {
            let Some(path) = self.item.as_ref().map(PathExpansionItem::path) else {
                // No item to expand. Indicate to the main iterator that it needs to fetch the next one
                return false;
            };

            if self.leaf_index == Self::UNKNOWN_INDEX {
                // The index of the expanded leaf is not yet known. Compute it.

                // Make sure we have a valid cluster position first
                if !self.next_cluster() {
                    break false;
                }
            }

            let cluster = &self.node.endpoints[self.endpoint_index].clusters[self.cluster_index];
            let cluster_leaves_len = if command {
                cluster.commands.len()
            } else {
                cluster.attributes.len()
            };

            if self.leaf_index == Self::UNKNOWN_INDEX {
                if let Some(leaf) = path.leaf {
                    // Non-wildcard leaf case

                    let leaf_index = if command {
                        cluster.commands.iter().position(|cmd: &u32| *cmd == leaf)
                    } else {
                        cluster
                            .attributes
                            .iter()
                            .position(|attr| attr.id == leaf as _)
                    };

                    let Some(leaf_index) = leaf_index else {
                        // This leaf does not exist in our meta-data
                        // Try to move to the next cluster
                        continue;
                    };

                    self.leaf_index = leaf_index;
                } else if cluster_leaves_len == 0 {
                    // No commands in the current cluster and the leaf is a wildcard one, move to the next cluster
                    continue;
                } else {
                    // Position on the first leaf for a leaf wildcard traversal
                    self.leaf_index = 0;
                }

                break true;
            }

            if path.leaf.is_some() || self.leaf_index == cluster_leaves_len - 1 {
                // Cannot move to the next leaf as the leaves of the current cluster are exchausted
                // or the leaf is a non-wildcard one.
                // Try to move to the next cluster
                self.leaf_index = Self::UNKNOWN_INDEX;
                continue;
            }

            // Move to the next leaf for a wildcard traversal
            self.leaf_index += 1;
            break true;
        }
    }
}

impl<'a, T, I> Iterator for PathExpander<'a, T, I>
where
    I: Iterator<Item = Result<T, Error>>,
    T: PathExpansionItem<'a>,
{
    type Item = Result<Result<T::Expanded<'a>, T::Status>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut just_fetched = false;

            // Fetch an item to expand if not already there
            if self.item.is_none() {
                let item = self.items.as_mut().and_then(|items| items.next())?;

                match item {
                    Err(err) => return Some(Err(err)),
                    Ok(item) => self.item = Some(item),
                }

                just_fetched = true;
            }

            // From here on, we do have a valid `self.item` to expand

            // Step on the first/next leaf of the item to be expanded
            if self.next_leaf() {
                // Stepped-in. All indices valid now

                let endpoint = &self.node.endpoints[self.endpoint_index];
                let cluster = &endpoint.clusters[self.cluster_index];

                let (leaf_id, check) = if matches!(T::LEAF_ACCESS, LeafAccess::Command) {
                    let command_id = cluster.commands[self.leaf_index];

                    (
                        command_id,
                        Cluster::check_cmd_access(
                            self.accessor,
                            GenericPath::new(Some(endpoint.id), Some(cluster.id), Some(command_id)),
                        ),
                    )
                } else {
                    let attr_id = cluster.attributes[self.leaf_index].id as _;

                    (
                        attr_id,
                        Cluster::check_attr_access(
                            self.accessor,
                            GenericPath::new(Some(endpoint.id), Some(cluster.id), Some(attr_id)),
                            matches!(T::LEAF_ACCESS, LeafAccess::AttrWrite),
                            cluster.attributes[self.leaf_index].access,
                        ),
                    )
                };

                if let Err(status) = check {
                    // Access check failed

                    if self.item.as_ref().unwrap().path().is_wildcard() {
                        // Wildcard path, skip to the next leaf rather than reporting an error
                        continue;
                    } else {
                        // Non-wildcard path, report an error and remove the current item
                        break Some(Ok(Err(self.item.take().unwrap().into_status(status))));
                    }
                } else {
                    // Access check succeeded

                    let expanded = self.item.as_ref().unwrap().expand(
                        self.node,
                        self.accessor,
                        endpoint.id,
                        cluster.id,
                        leaf_id,
                    );

                    break Some(expanded.map(Ok));
                }
            } else {
                if just_fetched && !self.item.as_ref().unwrap().path().is_wildcard() {
                    // Need to report an error status for non-wildcard paths which do not exist in our meta-data
                    let status;
                    if self.endpoint_index == Self::UNKNOWN_INDEX {
                        status = IMStatusCode::UnsupportedEndpoint;
                    } else if self.cluster_index == Self::UNKNOWN_INDEX {
                        status = IMStatusCode::UnsupportedCluster;
                    } else {
                        status = IMStatusCode::UnsupportedAttribute;
                    }

                    // Also remove the current item
                    break Some(Ok(Err(self.item.take().unwrap().into_status(status))));
                }

                // No error but since `next_leaf` returned `false`, the current item can no longer
                // be processed and we need to move to the next one
                self.item = None;
            }
        }
    }
}

/// Helper function to get the data version for a given endpoint and cluster
/// from the provided collection of filters
fn dataver(
    dataver_filters: Option<&TLVArray<DataVersionFilter>>,
    ep: EndptId,
    cl: ClusterId,
) -> Result<Option<u32>, Error> {
    if let Some(dataver_filters) = dataver_filters {
        for filter in dataver_filters {
            let filter = filter?;

            if filter.path.endpoint == ep && filter.path.cluster == cl {
                return Ok(Some(filter.data_ver));
            }
        }
    }

    Ok(None)
}
