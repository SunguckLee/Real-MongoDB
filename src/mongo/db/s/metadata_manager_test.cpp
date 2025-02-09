/**
 *    Copyright (C) 2016 MongoDB Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the GNU Affero General Public License in all respects
 *    for all of the code used other than as permitted herein. If you modify
 *    file(s) with this exception, you may extend this exception to your
 *    version of the file(s), but you are not obligated to do so. If you do not
 *    wish to do so, delete this exception statement from your version. If you
 *    delete this exception statement from all source files in the program,
 *    then also delete it in the license file.
 */

#include "mongo/platform/basic.h"

#include "mongo/db/s/metadata_manager.h"

#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/client.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/s/collection_metadata.h"
#include "mongo/db/s/sharding_state.h"
#include "mongo/db/service_context.h"
#include "mongo/db/service_context_d_test_fixture.h"
#include "mongo/s/catalog/type_chunk.h"
#include "mongo/stdx/memory.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/assert_util.h"

namespace mongo {
namespace {

using unittest::assertGet;

class MetadataManagerTest : public ServiceContextMongoDTest {
protected:
    void setUp() override {
        ServiceContextMongoDTest::setUp();
        ShardingState::get(getServiceContext())
            ->setScheduleCleanupFunctionForTest([](const NamespaceString& nss) {});
    }

    static std::unique_ptr<CollectionMetadata> makeEmptyMetadata() {
        const OID epoch = OID::gen();

        return stdx::make_unique<CollectionMetadata>(
            BSON("key" << 1),
            ChunkVersion(1, 0, epoch),
            ChunkVersion(0, 0, epoch),
            SimpleBSONObjComparator::kInstance.makeBSONObjIndexedMap<CachedChunkInfo>());
    }

    /**
     * Returns a new metadata's instance based on the current state by adding a chunk with the
     * specified bounds and version. The chunk's version must be higher than that of all chunks
     * which are in the input metadata.
     *
     * It will fassert if the chunk bounds are incorrect or overlap an existing chunk or if the
     * chunk version is lower than the maximum one.
     */
    static std::unique_ptr<CollectionMetadata> cloneMetadataPlusChunk(
        const CollectionMetadata& metadata,
        const BSONObj& minKey,
        const BSONObj& maxKey,
        const ChunkVersion& chunkVersion) {
        invariant(chunkVersion.epoch() == metadata.getShardVersion().epoch());
        invariant(chunkVersion.isSet());
        invariant(chunkVersion > metadata.getCollVersion());
        invariant(minKey.woCompare(maxKey) < 0);
        invariant(!rangeMapOverlaps(metadata.getChunks(), minKey, maxKey));

        auto chunksMap = metadata.getChunks();
        chunksMap.insert(
            std::make_pair(minKey.getOwned(), CachedChunkInfo(maxKey.getOwned(), chunkVersion)));

        return stdx::make_unique<CollectionMetadata>(
            metadata.getKeyPattern(), chunkVersion, chunkVersion, std::move(chunksMap));
    }

    std::shared_ptr<MetadataManager> manager_ptr{std::make_shared<MetadataManager>(
        getServiceContext(), NamespaceString("TestDb", "CollDB"))};
    MetadataManager& manager{*this->manager_ptr};
};

TEST_F(MetadataManagerTest, SetAndGetActiveMetadata) {
    std::unique_ptr<CollectionMetadata> cm = makeEmptyMetadata();
    auto cmPtr = cm.get();

    manager.refreshActiveMetadata(std::move(cm));
    ScopedCollectionMetadata scopedMetadata = manager.getActiveMetadata(manager_ptr);

    ASSERT_EQ(cmPtr, scopedMetadata.getMetadata());
};


TEST_F(MetadataManagerTest, ResetActiveMetadata) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ScopedCollectionMetadata scopedMetadata1 = manager.getActiveMetadata(manager_ptr);

    ChunkVersion newVersion = scopedMetadata1->getCollVersion();
    newVersion.incMajor();
    std::unique_ptr<CollectionMetadata> cm2 = cloneMetadataPlusChunk(
        *scopedMetadata1.getMetadata(), BSON("key" << 0), BSON("key" << 10), newVersion);
    auto cm2Ptr = cm2.get();

    manager.refreshActiveMetadata(std::move(cm2));
    ScopedCollectionMetadata scopedMetadata2 = manager.getActiveMetadata(manager_ptr);

    ASSERT_EQ(cm2Ptr, scopedMetadata2.getMetadata());
};

TEST_F(MetadataManagerTest, AddAndRemoveRangesToClean) {
    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));
    ChunkRange cr2 = ChunkRange(BSON("key" << 10), BSON("key" << 20));

    manager.addRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    manager.removeRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);

    manager.addRangeToClean(cr1);
    manager.addRangeToClean(cr2);
    manager.removeRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    auto ranges = manager.getCopyOfRangesToClean();
    auto it = ranges.find(cr2.getMin());
    ChunkRange remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    ASSERT_EQ(remainingChunk.toString(), cr2.toString());
    manager.removeRangeToClean(cr2);
}

// Tests that a removal in the middle of an existing ChunkRange results in
// two correct chunk ranges.
TEST_F(MetadataManagerTest, RemoveRangeInMiddleOfRange) {
    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));

    manager.addRangeToClean(cr1);
    manager.removeRangeToClean(ChunkRange(BSON("key" << 4), BSON("key" << 6)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 2UL);

    auto ranges = manager.getCopyOfRangesToClean();
    auto it = ranges.find(BSON("key" << 0));
    ChunkRange expectedChunk = ChunkRange(BSON("key" << 0), BSON("key" << 4));
    ChunkRange remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    it++;
    expectedChunk = ChunkRange(BSON("key" << 6), BSON("key" << 10));
    remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    manager.removeRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

// Tests removals that overlap with just one ChunkRange.
TEST_F(MetadataManagerTest, RemoveRangeWithSingleRangeOverlap) {
    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));

    manager.addRangeToClean(cr1);
    manager.removeRangeToClean(ChunkRange(BSON("key" << 0), BSON("key" << 5)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    auto ranges = manager.getCopyOfRangesToClean();
    auto it = ranges.find(BSON("key" << 5));
    ChunkRange remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    ChunkRange expectedChunk = ChunkRange(BSON("key" << 5), BSON("key" << 10));
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    manager.removeRangeToClean(ChunkRange(BSON("key" << 4), BSON("key" << 6)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    ranges = manager.getCopyOfRangesToClean();
    it = ranges.find(BSON("key" << 6));
    remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    expectedChunk = ChunkRange(BSON("key" << 6), BSON("key" << 10));
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    manager.removeRangeToClean(ChunkRange(BSON("key" << 9), BSON("key" << 13)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    ranges = manager.getCopyOfRangesToClean();
    it = ranges.find(BSON("key" << 6));
    remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    expectedChunk = ChunkRange(BSON("key" << 6), BSON("key" << 9));
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    manager.removeRangeToClean(ChunkRange(BSON("key" << 0), BSON("key" << 10)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

// Tests removals that overlap with more than one ChunkRange.
TEST_F(MetadataManagerTest, RemoveRangeWithMultipleRangeOverlaps) {
    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));
    ChunkRange cr2 = ChunkRange(BSON("key" << 10), BSON("key" << 20));
    ChunkRange cr3 = ChunkRange(BSON("key" << 20), BSON("key" << 30));

    manager.addRangeToClean(cr1);
    manager.addRangeToClean(cr2);
    manager.addRangeToClean(cr3);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 3UL);

    manager.removeRangeToClean(ChunkRange(BSON("key" << 8), BSON("key" << 22)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 2UL);
    auto ranges = manager.getCopyOfRangesToClean();
    auto it = ranges.find(BSON("key" << 0));
    ChunkRange remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    ChunkRange expectedChunk = ChunkRange(BSON("key" << 0), BSON("key" << 8));
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());
    it++;
    remainingChunk = ChunkRange(it->first, it->second.getMaxKey());
    expectedChunk = ChunkRange(BSON("key" << 22), BSON("key" << 30));
    ASSERT_EQ(remainingChunk.toString(), expectedChunk.toString());

    manager.removeRangeToClean(ChunkRange(BSON("key" << 0), BSON("key" << 30)));
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

TEST_F(MetadataManagerTest, AddAndRemoveRangeNotificationsBlockAndYield) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    auto notification = manager.addRangeToClean(cr1);
    manager.removeRangeToClean(cr1, Status::OK());
    ASSERT_OK(notification->get());
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

TEST_F(MetadataManagerTest, RemoveRangeToCleanCorrectlySetsBadStatus) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    auto notification = manager.addRangeToClean(cr1);
    manager.removeRangeToClean(cr1, Status(ErrorCodes::InternalError, "test error"));
    ASSERT_NOT_OK(notification->get());
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

TEST_F(MetadataManagerTest, RemovingSubrangeStillSetsNotificationStatus) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    auto notification = manager.addRangeToClean(cr1);
    manager.removeRangeToClean(ChunkRange(BSON("key" << 3), BSON("key" << 7)));
    ASSERT_OK(notification->get());
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 2UL);
    manager.removeRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);

    notification = manager.addRangeToClean(cr1);
    manager.removeRangeToClean(ChunkRange(BSON("key" << 7), BSON("key" << 15)));
    ASSERT_OK(notification->get());
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 1UL);
    manager.removeRangeToClean(cr1);
    ASSERT_EQ(manager.getCopyOfRangesToClean().size(), 0UL);
}

TEST_F(MetadataManagerTest, NotificationBlocksUntilDeletion) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    auto notification = manager.addRangeToClean(cr1);
    auto txn = cc().makeOperationContext().get();
    // Once the new range deleter is set up, this might fail if the range deleter
    // deleted cr1 before we got here...
    ASSERT_FALSE(notification->waitFor(txn, Milliseconds(0)));

    manager.removeRangeToClean(cr1);
    ASSERT_TRUE(notification->waitFor(txn, Milliseconds(0)));
    ASSERT_OK(notification->get());
}


TEST_F(MetadataManagerTest, RefreshAfterSuccessfulMigrationSinglePending) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    const ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    manager.beginReceive(cr1);
    ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 1UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 0UL);

    ChunkVersion version = manager.getActiveMetadata(manager_ptr)->getCollVersion();
    version.incMajor();

    manager.refreshActiveMetadata(
        cloneMetadataPlusChunk(*manager.getActiveMetadata(manager_ptr).getMetadata(),
                               cr1.getMin(),
                               cr1.getMax(),
                               version));
    ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 0UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 1UL);
}

TEST_F(MetadataManagerTest, RefreshAfterSuccessfulMigrationMultiplePending) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    const ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    manager.beginReceive(cr1);

    const ChunkRange cr2(BSON("key" << 30), BSON("key" << 40));
    manager.beginReceive(cr2);

    ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 2UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 0UL);

    {
        ChunkVersion version = manager.getActiveMetadata(manager_ptr)->getCollVersion();
        version.incMajor();

        manager.refreshActiveMetadata(
            cloneMetadataPlusChunk(*manager.getActiveMetadata(manager_ptr).getMetadata(),
                                   cr1.getMin(),
                                   cr1.getMax(),
                                   version));
        ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 1UL);
        ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 1UL);
    }

    {
        ChunkVersion version = manager.getActiveMetadata(manager_ptr)->getCollVersion();
        version.incMajor();

        manager.refreshActiveMetadata(
            cloneMetadataPlusChunk(*manager.getActiveMetadata(manager_ptr).getMetadata(),
                                   cr2.getMin(),
                                   cr2.getMax(),
                                   version));
        ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 0UL);
        ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 2UL);
    }
}

TEST_F(MetadataManagerTest, RefreshAfterNotYetCompletedMigrationMultiplePending) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    const ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    manager.beginReceive(cr1);

    const ChunkRange cr2(BSON("key" << 30), BSON("key" << 40));
    manager.beginReceive(cr2);

    ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 2UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 0UL);

    ChunkVersion version = manager.getActiveMetadata(manager_ptr)->getCollVersion();
    version.incMajor();

    manager.refreshActiveMetadata(
        cloneMetadataPlusChunk(*manager.getActiveMetadata(manager_ptr).getMetadata(),
                               BSON("key" << 50),
                               BSON("key" << 60),
                               version));
    ASSERT_EQ(manager.getCopyOfReceivingChunks().size(), 2UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 1UL);
}

TEST_F(MetadataManagerTest, BeginReceiveWithOverlappingRange) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    const ChunkRange cr1(BSON("key" << 0), BSON("key" << 10));
    manager.beginReceive(cr1);

    const ChunkRange cr2(BSON("key" << 30), BSON("key" << 40));
    manager.beginReceive(cr2);

    const ChunkRange crOverlap(BSON("key" << 5), BSON("key" << 35));
    manager.beginReceive(crOverlap);

    const auto copyOfPending = manager.getCopyOfReceivingChunks();

    ASSERT_EQ(copyOfPending.size(), 1UL);
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 0UL);

    const auto it = copyOfPending.find(BSON("key" << 5));
    ASSERT(it != copyOfPending.end());
    ASSERT_BSONOBJ_EQ(it->second.getMaxKey(), BSON("key" << 35));
}

TEST_F(MetadataManagerTest, RefreshMetadataAfterDropAndRecreate) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    {
        auto metadata = manager.getActiveMetadata(manager_ptr);
        ChunkVersion newVersion = metadata->getCollVersion();
        newVersion.incMajor();

        manager.refreshActiveMetadata(cloneMetadataPlusChunk(
            *metadata.getMetadata(), BSON("key" << 0), BSON("key" << 10), newVersion));
    }

    // Now, pretend that the collection was dropped and recreated
    auto recreateMetadata = makeEmptyMetadata();
    ChunkVersion newVersion = recreateMetadata->getCollVersion();
    newVersion.incMajor();

    manager.refreshActiveMetadata(cloneMetadataPlusChunk(
        *recreateMetadata, BSON("key" << 20), BSON("key" << 30), newVersion));
    ASSERT_EQ(manager.getActiveMetadata(manager_ptr)->getChunks().size(), 1UL);

    const auto chunkEntry = manager.getActiveMetadata(manager_ptr)->getChunks().begin();
    ASSERT_BSONOBJ_EQ(BSON("key" << 20), chunkEntry->first);
    ASSERT_BSONOBJ_EQ(BSON("key" << 30), chunkEntry->second.getMaxKey());
    ASSERT_EQ(newVersion, chunkEntry->second.getVersion());
}

// Tests membership functions for _rangesToClean
TEST_F(MetadataManagerTest, RangesToCleanMembership) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ASSERT(!manager.hasRangesToClean());

    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));
    manager.addRangeToClean(cr1);

    ASSERT(manager.hasRangesToClean());
    ASSERT(manager.isInRangesToClean(cr1));
}

// Tests that getNextRangeToClean successfully pulls a stored ChunkRange
TEST_F(MetadataManagerTest, GetNextRangeToClean) {
    manager.refreshActiveMetadata(makeEmptyMetadata());

    ChunkRange cr1 = ChunkRange(BSON("key" << 0), BSON("key" << 10));
    manager.addRangeToClean(cr1);

    ChunkRange cr2 = manager.getNextRangeToClean();
    ASSERT_EQ(cr1.toString(), cr2.toString());
}

}  // namespace
}  // namespace mongo
