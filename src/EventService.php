<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class EventService
{
    public function __construct(private Database $db) {}

    public function emit(string $type, array $payload = [], ?int $organizationId = null): string
    {
        $uuid = Security::uuidV4();
        $this->db->execute('INSERT INTO event_outbox(event_uuid,organization_id,event_type,payload_json) VALUES(?,?,?,?)', [$uuid,$organizationId,$type,json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)]);
        return $uuid;
    }
}
