export async function mapInBatches(items, batchSize, mapper) {
    if (!Array.isArray(items) || items.length === 0) {
        return [];
    }
    const limit = Math.max(1, Number.isFinite(batchSize) ? Math.floor(batchSize) : 1);
    const results = [];
    for (let index = 0; index < items.length; index += limit) {
        const slice = items.slice(index, index + limit);
        const chunk = await Promise.all(slice.map((item, sliceIndex) => mapper(item, index + sliceIndex)));
        results.push(...chunk);
    }
    return results;
}

