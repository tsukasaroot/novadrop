using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization.Items;

namespace Vezel.Novadrop.Data.Serialization.Readers;

sealed class EagerImmutableDataCenterReader : DataCenterReader
{
    static readonly OrderedDictionary<string, DataCenterValue> _emptyAttributes = new();

    static readonly List<DataCenterNode> _emptyChildren = new();

    readonly Dictionary<DataCenterAddress, EagerImmutableDataCenterNode> _cache = new();

    public EagerImmutableDataCenterReader(DataCenterLoadOptions options)
        : base(options)
    {
    }

    protected override EagerImmutableDataCenterNode AllocateNode(
        DataCenterAddress address,
        DataCenterRawNode raw,
        object parent,
        string name,
        string? value,
        DataCenterKeys keys,
        CancellationToken cancellationToken)
    {
        var node = new EagerImmutableDataCenterNode(parent, name, value, keys);

        _cache.Add(address, node);

        var attributes = _emptyAttributes;

        if (raw.AttributeCount - (value != null ? 1 : 0) != 0)
        {
            attributes = new OrderedDictionary<string, DataCenterValue>(raw.AttributeCount);

            ReadAttributes(raw, attributes, static (attributes, name, value) =>
            {
                if (!attributes.TryAdd(name, value))
                    throw new InvalidDataException($"Attribute named '{name}' was already recorded earlier.");
            });
        }

        var children = _emptyChildren;

        if (raw.ChildCount != 0)
        {
            children = new List<DataCenterNode>(raw.ChildCount);

            ReadChildren(raw, node, children, static (children, node) => children.Add(node), cancellationToken);
        }

        node.Initialize(attributes, children);

        return node;
    }

    protected override EagerImmutableDataCenterNode? ResolveNode(
        DataCenterAddress address, object parent, CancellationToken cancellationToken)
    {
        return _cache.GetValueOrDefault(address) ??
            Unsafe.As<EagerImmutableDataCenterNode>(CreateNode(address, parent, cancellationToken));
    }
}
