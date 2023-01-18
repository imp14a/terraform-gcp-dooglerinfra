/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

module "vpc" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-vpc"
  project_id = var.globals.project_id
  name       = "${local.prefix}-vpc"
  subnets    = var.subnets
}

module "firewall" {
  source       = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-vpc-firewall"
  project_id   = var.globals.project_id
  network      = module.vpc.name
  admin_ranges = var.admin_ranges
}

module "nat" {
  source         = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-cloudnat"
  project_id     = var.globals.project_id
  region         = var.region
  name           = "default"
  router_network = module.vpc.name
}

# Static ip for external infress for cluster
resource "google_compute_address" "static" {
  name = "ipv4-address"
}
