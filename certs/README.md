# certs/ — Certificats TLS

Ce répertoire est **gitignorié** (sauf ce fichier). Il n'est pas peuplé automatiquement.

Les fichiers réels (clés privées, certificats) ne doivent **jamais** être commités.

---

## Structure attendue

```
certs/
├── ca.crt        # CA racine — vérifie les certificats clients et serveur
├── server.crt    # Certificat serveur Fluent Bit (signé par ca.crt)
├── server.key    # Clé privée serveur (permissions 600)
├── client.crt    # Certificat client syslog (signé par ca.crt) — mTLS complet
└── client.key    # Clé privée client (permissions 600)
```

Les fichiers `*.csr` (Certificate Signing Request) sont intermédiaires et peuvent être supprimés après génération.

---

## Génération (labo / démonstration uniquement)

```bash
# Génère tous les certificats nécessaires dans ./certs/
./scripts/gen_certs.sh ./certs

# Copier dans le volume Docker nommé 'certs'
docker run --rm \
  -v $(pwd)/certs:/src \
  -v certs:/dest \
  alpine cp -r /src/. /dest/
```

Le script `gen_certs.sh` produit des certificats **auto-signés** à durée limitée (CA : 10 ans, certs : 1 an).
Ces certificats sont **uniquement adaptés au labo / développement**.

---

## Production

En production conforme ANSSI :
- Les certificats doivent être émis par une PKI d'entreprise
- Les clés privées doivent être stockées dans un HSM ou un gestionnaire de secrets (Vault, etc.)
- La rotation doit être automatisée
- `tls.verify On` doit être maintenu côté Fluent Bit

---

## Vérification

```bash
# Vérifier le contenu du volume Docker
docker run --rm -v certs:/certs alpine ls -la /certs/

# Vérifier qu'un certificat est valide et signé par le CA
openssl verify -CAfile ./certs/ca.crt ./certs/server.crt

# Voir les détails d'un certificat
openssl x509 -in ./certs/server.crt -text -noout | grep -E "Subject|Issuer|Not After|DNS"
```
