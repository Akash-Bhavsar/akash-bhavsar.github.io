---
layout: page
title: Projects
permalink: /projects/
description: Security projects and open-source tools.
nav: true
nav_order: 3
display_categories: [security]
horizontal: false
---

<!-- pages/projects.md -->
<div class="projects">
{%- if site.enable_project_categories and page.display_categories %}
  {%- for category in page.display_categories %}
  <a id="{{ category }}" href=".#{{ category }}">
    <h2 class="category">{{ category }}</h2>
  </a>
  {%- assign categorized_projects = site.projects | where: "category", category -%}
  {%- assign sorted_projects = categorized_projects | sort: "importance" %}
  {%- if page.horizontal -%}
  <div class="container">
    <div class="row row-cols-2">
    {%- for project in sorted_projects -%}
      {% include projects_horizontal.liquid project=project %}
    {%- endfor %}
    </div>
  </div>
  {%- else -%}
  <div class="container">
    <div class="row row-cols-1 row-cols-md-2">
    {%- for project in sorted_projects -%}
      {% include projects.liquid project=project %}
    {%- endfor %}
    </div>
  </div>
  {%- endif -%}
  {%- endfor -%}
{%- else -%}
  {%- assign sorted_projects = site.projects | sort: "importance" -%}
  {%- if page.horizontal -%}
  <div class="container">
    <div class="row row-cols-2">
    {%- for project in sorted_projects -%}
      {% include projects_horizontal.liquid project=project %}
    {%- endfor %}
    </div>
  </div>
  {%- else -%}
  <div class="container">
    <div class="row row-cols-1 row-cols-md-2">
    {%- for project in sorted_projects -%}
      {% include projects.liquid project=project %}
    {%- endfor %}
    </div>
  </div>
  {%- endif -%}
{%- endif -%}
</div>
