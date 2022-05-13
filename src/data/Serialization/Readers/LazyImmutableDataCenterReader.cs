using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization.Items;

namespace Vezel.Novadrop.Data.Serialization.Readers;

sealed class LazyImmutableDataCenterReader : DataCenterReader
{
    static readonly OrderedDictionary<string, DataCenterValue> _emptyAttributes = new();

    static readonly List<DataCenterNode> _emptyChildren = new();

    readonly ConcurrentDictionary<DataCenterAddress, LazyImmutableDataCenterNode> _cache = new();

    public LazyImmutableDataCenterReader(DataCenterLoadOptions options)
        : base(options)
    {
    }

    protected override LazyImmutableDataCenterNode AllocateNode(
        DataCenterAddress address,
        DataCenterRawNode raw,
        object parent,
        string name,
        string? value,
        DataCenterKeys keys,
        CancellationToken cancellationToken)
    {
        // This may result in redundant node allocations, but that has no side effects anyway, and only one wins.
        return _cache.GetOrAdd(
            address,
            _ =>
            {
                LazyImmutableDataCenterNode node = null!;

                return node = new LazyImmutableDataCenterNode(
                    parent,
                    name,
                    value,
                    keys,
                    () =>
                    {
                        var attributes = _emptyAttributes;

                        if (raw.AttributeCount - (value != null ? 1 : 0) != 0)
                        {
                            attributes = new OrderedDictionary<string, DataCenterValue>(raw.AttributeCount);

                            ReadAttributes(raw, attributes, static (attributes, name, value) =>
                            {
                                if (!attributes.TryAdd(name, value))
                                    throw new InvalidDataException(
                                        $"Attribute named '{name}' was already recorded earlier.");
                            });
                        }

                        return attributes;
                    },
                    () =>
                    {
                        var children = _emptyChildren;

                        if (raw.ChildCount != 0)
                        {
                            children = new List<DataCenterNode>(raw.ChildCount);

                            ReadChildren(raw, node, children, static (children, node) => children.Add(node), default);
                        }

                        return children;
                    });
            });
    }

    protected override LazyImmutableDataCenterNode? ResolveNode(
        DataCenterAddress address, object parent, CancellationToken cancellationToken)
    {
        return _cache.GetValueOrDefault(address) ??
            Unsafe.As<LazyImmutableDataCenterNode>(CreateNode(address, parent, default));
    }
}
