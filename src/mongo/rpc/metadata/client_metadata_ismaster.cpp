/**
 * Copyright (C) 2016 MongoDB Inc.
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, the copyright holders give permission to link the
 * code of portions of this program with the OpenSSL library under certain
 * conditions as described in each individual source file and distribute
 * linked combinations including the program with the OpenSSL library. You
 * must comply with the GNU Affero General Public License in all respects
 * for all of the code used other than as permitted herein. If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version. If you
 * delete this exception statement from all source files in the program,
 * then also delete it in the license file.
 */

#include "mongo/platform/basic.h"

#include "mongo/rpc/metadata/client_metadata_ismaster.h"

#include <string>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/db/client.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/service_context.h"
#include "mongo/stdx/memory.h"

namespace mongo {

namespace {

const auto getClientMetadataIsMasterState =
    Client::declareDecoration<ClientMetadataIsMasterState>();

}  // namespace

ClientMetadataIsMasterState& ClientMetadataIsMasterState::get(Client* client) {
    return getClientMetadataIsMasterState(*client);
}

bool ClientMetadataIsMasterState::hasSeenIsMaster() const {
    return _hasSeenIsMaster;
}

void ClientMetadataIsMasterState::setSeenIsMaster() {
    invariant(!_hasSeenIsMaster);
    _hasSeenIsMaster = true;
}

const boost::optional<ClientMetadata>& ClientMetadataIsMasterState::getClientMetadata() const {
    return _clientMetadata;
}

void ClientMetadataIsMasterState::setClientMetadata(
    Client* client, boost::optional<ClientMetadata> clientMetadata) {
    auto& state = get(client);

    stdx::lock_guard<Client> lk(*client);
    state._clientMetadata = std::move(clientMetadata);
}


Status ClientMetadataIsMasterState::readFromMetadata(OperationContext* txn, BSONElement& element) {
    if (element.eoo()) {
        return Status::OK();
    }

    auto swParseClientMetadata = ClientMetadata::parse(element);

    if (!swParseClientMetadata.getStatus().isOK()) {
        return swParseClientMetadata.getStatus();
    }

    auto& clientMetadataIsMasterState = ClientMetadataIsMasterState::get(txn->getClient());

    clientMetadataIsMasterState.setClientMetadata(txn->getClient(),
                                                  std::move(swParseClientMetadata.getValue()));

    return Status::OK();
}

void ClientMetadataIsMasterState::writeToMetadata(OperationContext* txn, BSONObjBuilder* builder) {
    // We may be asked to write metadata on background threads that are not associated with an
    // operation context
    if (!txn) {
        return;
    }

    const auto& clientMetadata =
        ClientMetadataIsMasterState::get(txn->getClient()).getClientMetadata();

    // Skip appending metadata if there is none
    if (!clientMetadata || clientMetadata.get().getDocument().isEmpty()) {
        return;
    }

    builder->append(ClientMetadata::fieldName(), clientMetadata.get().getDocument());
}

}  // namespace mongo
