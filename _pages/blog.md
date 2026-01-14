---
layout: page
permalink: /blog/
title: Security Blog
nav: false
nav_order: 3
description: Security research, penetration testing writeups, and application security insights.
---

<div class="post">
  {% if site.posts.size > 0 %}
    <ul class="post-list">
      {% for post in site.posts %}
        <li>
          <article class="post-card">
            <h3>
              <a class="post-link" href="{{ post.url | relative_url }}">{{ post.title }}</a>
            </h3>
            <p class="post-meta">
              {{ post.date | date: "%B %-d, %Y" }}
              {% if post.tags.size > 0 %}
                &nbsp;•&nbsp;
                {% for tag in post.tags %}
                  <span class="badge">{{ tag }}</span>
                {% endfor %}
              {% endif %}
            </p>
            <p class="post-description">{{ post.description }}</p>
          </article>
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p>No posts yet. Check back soon for security research and writeups!</p>
  {% endif %}
</div>
