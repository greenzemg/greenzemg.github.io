# Are you lost or is it your first time here?



### Local Development
```bash
bundle exec jekyll serve
```

### Or with live reload
bundle exec jekyll serve --livereload

### Making modifications
- About page: Edit about.md
- Projects: Edit files in _projects folder
- Blog posts: Add new files in _posts
- CV: Edit cv.yml

### Configuration changes
- Site settings: Edit _config.yml
- Navigation: Modify _pages files
- Styling: Edit files in _sass folder

### Building the site
```
# Build the site
bundle exec jekyll build --lsi
```

### Deployment
```bash
# Deploy to GitHub Pages
git add .
git commit -m "Update site"
git push origin main
```

### Summary of the workflow
1. Make changes to content or configuration.
2. Test locally with `bundle exec jekyll serve`.
3. Commit changes to Git.
4. Push to GitHub - automatic deployment will trigger.
5. Check the live site for updates.

### Common Commands
```bash
# Start local development server
bundle exec jekyll serve --livereload

# Build for production
bundle exec jekyll build --lsi

# Clean build files
bundle exec jekyll clean

# Update gems
bundle update

# Check for issues
bundle exec jekyll doctor
```

# Troubleshooting


### Project Structure for Modifications

- _config.yml - Main configuration
- _pages - Static pages (About, Projects, etc.)
- _posts - Blog posts
- _projects - Project entries
- _data - Data files (CV, etc.)
- assets - Images, CSS, JS files
- _sass - Stylesheets
- _includes - Reusable HTML components
- _layouts - Page templates