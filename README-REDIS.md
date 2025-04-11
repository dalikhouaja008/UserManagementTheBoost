# Guide d'Installation Redis pour TheBoost Backend
**Date de dernière mise à jour**: 2025-03-09 19:31:10  

## Prérequis
- Docker Desktop installé
- Docker Compose installé
- Accès aux ports 6379 (Redis)

## 1. Structure du Projet

the-boost_backend/
├── src/
│   └── redis/
│       └── redis-cache.module.ts     # module Redis
        └── redis-cache.service.ts    # service  Redis 
├── docker-compose.yml         # Configuration Docker Compose
├── .env                      # Variables d'environnement
└── README-REDIS.md           # Ce guide
```

## 2. Configuration Docker Compose

Créez ou mettez à jour votre fichier `docker-compose.yml` :

```services:
  redis:
    image: redis:latest
    container_name: the-boost-redis
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

## 3. Variables d'Environnement

Créez ou mettez à jour votre fichier `.env` :

```env
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL=redis://${REDIS_HOST}:${REDIS_PORT}
```

## 4. Installation et Démarrage

1. **Démarrer Redis** :
```bash
# Depuis le répertoire racine du projet
docker-compose up -d redis
```

2. **Vérifier que Redis fonctionne** :
```bash
# Vérifier le statut du conteneur
docker ps | grep redis

# Vérifier les logs
docker logs boost-redis

# Tester la connexion Redis
docker exec -it boost-redis redis-cli ping
# Devrait répondre "PONG"
```

## 5. Commandes Utiles

### Gestion des Conteneurs
```bash
# Démarrer Redis
docker-compose up -d redis

# Arrêter Redis
docker-compose stop redis

# Redémarrer Redis
docker-compose restart redis

# Arrêter et supprimer le conteneur
docker-compose down redis

# Supprimer le conteneur et les données
docker-compose down -v redis
```

### Déboggage
```bash
# Voir les logs en temps réel
docker logs -f boost-redis

# Se connecter au CLI Redis
docker exec -it boost-redis redis-cli

# Vérifier la connexion réseau
docker network inspect boost-network
```

## 6. Résolution des Problèmes Courants

### Erreur "Connection Refused"
```bash
# 1. Vérifier que le conteneur est en cours d'exécution
docker ps | grep redis

# 2. Vérifier les logs pour des erreurs
docker logs boost-redis

# 3. Redémarrer le conteneur
docker-compose restart redis
```

### Port déjà utilisé
```bash
# 1. Vérifier si le port 6379 est déjà utilisé
netstat -ano | findstr :6379

# 2. Modifier le port dans docker-compose.yml si nécessaire
ports:
  - "6380:6379"  # Utilise le port 6380 en local
```

### Problèmes de Persistance
```bash
# 1. Vérifier les volumes
docker volume ls | grep redis

# 2. Inspecter le volume
docker volume inspect boost-redis-data

# 3. Nettoyer et recréer le volume si nécessaire
docker-compose down -v
docker-compose up -d redis
```

## 7. Tests de Vérification

```bash
# 1. Connexion au CLI Redis
docker exec -it boost-redis redis-cli

# 2. Tests basiques
> SET test "Hello World"
> GET test
> PING
```

## 8. Maintenance

### Sauvegardes
```bash
# Créer une sauvegarde
docker exec boost-redis redis-cli SAVE

# Localisation de la sauvegarde
/data/dump.rdb

#vider le cache
redis-cli FLUSHALL
```

### Mises à Jour
```bash
# 1. Mettre à jour l'image Redis
docker-compose pull redis

# 2. Redémarrer le service
docker-compose up -d redis
```

## 9. Support

Pour toute question ou problème :
1. Vérifiez les logs Docker
2. Consultez la documentation Redis
3. Contactez l'équipe DevOps

## 10. Notes de Sécurité

- Le port Redis (6379) ne devrait être accessible qu'en local
- Utilisez des mots de passe forts en production
- Limitez l'accès réseau en production

---

**Remarque**: Ce guide suppose une installation locale/développement. Pour la production, des configurations de sécurité supplémentaires sont nécessaires.