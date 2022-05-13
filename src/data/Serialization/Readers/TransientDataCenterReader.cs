using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization.Items;

namespace Vezel.Novadrop.Data.Serialization.Readers;

sealed class TransientDataCenterReader : DataCenterReader
{
    static readonly OrderedDictionary<string, DataCenterValue> _emptyAttributes = new();

    static readonly List<DataCenterNode> _emptyChildren = new();

    public TransientDataCenterReader(DataCenterLoadOptions options)
        : base(options)
    {
    }

    protected override DataCenterNode AllocateNode(
        DataCenterAddress address,
        DataCenterRawNode raw,
        object parent,
        string name,
        string? value,
        DataCenterKeys keys,
        CancellationToken cancellationToken)
    {
        TransientDataCenterNode node = null!;

        return node = new TransientDataCenterNode(
            parent,
            name,
            value,
            keys,
            raw.AttributeCount - (value != null ? 1 : 0) != 0,
            raw.ChildCount != 0,
            () =>
            {
                var attributes = _emptyAttributes;

                if (node.HasAttributes)
                {
                    attributes = new OrderedDictionary<string, DataCenterValue>(raw.AttributeCount);

                    ReadAttributes(raw, attributes, static (attributes, name, value) =>
                    {
                        if (!attributes.TryAdd(name, value))
                            throw new InvalidDataException($"Attribute named '{name}' was already recorded earlier.");
                    });
                }

                return attributes;
            },
            () =>
            {
                var children = _emptyChildren;

                if (node.HasChildren)
                {
                    children = new List<DataCenterNode>(raw.ChildCount);

                    ReadChildren(raw, node, children, static (children, node) => children.Add(node), default);
                }

                return children;
            });
    }

    protected override DataCenterNode? ResolveNode(
        DataCenterAddress address, object parent, CancellationToken cancellationToken)
    {
        return CreateNode(address, parent, default);
    }
}
