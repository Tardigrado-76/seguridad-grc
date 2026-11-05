terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Cloud SQL - PostgreSQL (Replacing SQLite)
resource "google_sql_database_instance" "quantigrade_db" {
  name             = "quantigrade-db-primary"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
      point_in_time_recovery_enabled = true
    }
  }
  deletion_protection = false # for dev/demo purposes
}

resource "google_sql_database" "langgraph_db" {
  name     = "langgraph"
  instance = google_sql_database_instance.quantigrade_db.name
}

# Secret Manager (Replacing Vault for local dev if chosen, or syncing)
resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "quantigrade-jwt-secret"
  replication {
    auto {}
  }
}

# Pub/Sub (For Agent EventBus)
resource "google_pubsub_topic" "agent_events" {
  name = "quantigrade-agent-events"
}

resource "google_pubsub_subscription" "agent_events_sub" {
  name  = "quantigrade-agent-events-sub"
  topic = google_pubsub_topic.agent_events.name
}