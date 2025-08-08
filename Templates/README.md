# Microsoft Extractor Suite - JSON Templates

This directory contains JSON-based investigation templates that provide a more UI-friendly alternative to PowerShell hash tables. The templates are structured to enable consistent configuration and execution of security investigations.

## Template Structure

### Schema
The `schema.json` file defines the complete structure for investigation templates, including:
- **Metadata**: Template name, description, category, and execution estimates
- **Task Categories**: Organized groups of investigation tasks
- **UAL Operations**: Unified Audit Log operations grouped by security domain

### Available Templates

1. **Quick.json** - Rapid security triage template
   - Fast execution with essential security tasks
   - Focused on high-priority security events
   - Minimal resource usage

2. **Standard.json** - Balanced investigation template
   - Comprehensive coverage of key data sources
   - Moderate execution time and resource usage
   - Default choice for most investigations

3. **Comprehensive.json** - Full-depth investigation template
   - Maximum data collection coverage
   - Extensive execution time
   - All available data sources (most disabled by default)

4. **Custom.json** - Customizable template
   - All tasks disabled by default
   - Allows selective enabling of specific tasks
   - Flexible for specific investigation needs

## Template Categories

### Core Security Analysis
- Risky users and risk detections
- MFA status collection
- Mailbox rules analysis
- OAuth permissions review

### Authentication & Logging
- Sign-in logs collection
- Audit logs analysis
- Directory activity tracking

### User Management
- User information gathering
- Administrative privilege mapping
- Device registration data

### Tenant-Wide Configuration
- Security policies and settings
- Conditional access policies
- License and compliance data

### Unified Audit Log Operations
Organized by security domain:
- Email rules & configuration
- Authentication & identity events
- File & SharePoint activities
- Administrative activities
- Security & compliance events

## JSON Template Advantages

### 1. UI-Friendly Structure
- Hierarchical organization with categories
- Boolean flags for enabling/disabling tasks
- Risk level indicators for prioritization
- Human-readable descriptions

### 2. Metadata Rich
- Execution time estimates
- Task dependencies
- Resource impact indicators
- Tenant-wide vs. user-specific modes

### 3. Validation Support
- JSON schema validation
- Type safety for configuration
- Consistent structure across templates

### 4. Tool Integration
- Easy parsing for UI applications
- REST API friendly format
- Standard tooling support

## Proposed Cmdlets

### Get-MESTemplates
Retrieves available investigation templates with filtering options.

```powershell
# Get all templates
Get-MESTemplates

# Get specific category
Get-MESTemplates -Category "Quick"

# Include disabled tasks
Get-MESTemplates -IncludeDisabled

# Use custom template path
Get-MESTemplates -TemplatePath "C:\CustomTemplates"
```

### New-MESTemplate
Creates new custom templates with optional base template copying.

```powershell
# Create new custom template
New-MESTemplate -Name "Insider Threat" -Description "Focused on insider threat detection"

# Create based on existing template
$standardTemplate = Get-MESTemplates -Category "Standard"
New-MESTemplate -Name "Custom Standard" -BaseTemplate $standardTemplate[0] -OutputPath ".\Custom.json"
```

### Export-MESTemplateConfig
Exports template configuration for execution.

```powershell
# Export enabled tasks only
$template = Get-MESTemplates -Category "Quick"
Export-MESTemplateConfig -Template $template[0] -EnabledOnly -OutputPath ".\config.json"
```

### ConvertTo-MESJsonTemplate
Converts existing PowerShell templates to JSON format.

```powershell
# Convert PowerShell template
ConvertTo-MESJsonTemplate -PowerShellTemplatePath ".\Templates\Standard.psd1" -OutputPath ".\Standard.json"
```

## Template Execution Flow

1. **Template Selection**: Choose appropriate template based on investigation scope
2. **Customization**: Enable/disable tasks based on specific requirements
3. **Validation**: Verify template configuration against schema
4. **Execution**: Run investigation using template configuration
5. **Reporting**: Generate results based on template metadata

## Integration Benefits

### For Developers
- Type-safe configuration objects
- Consistent API interfaces
- Easy template validation
- Extensible structure

### For Users
- Clear task organization
- Visual representation support
- Risk-based prioritization
- Execution time estimates

### For UIs
- Hierarchical display support
- Category-based filtering
- Progress tracking metadata
- Resource impact indicators

## Migration from PowerShell Templates

The JSON templates maintain compatibility with existing PowerShell-based workflows while providing enhanced structure and metadata. The conversion process preserves:
- Task definitions and commands
- UAL operation specifications
- Enabling/disabling logic
- Category organization

Additional benefits include:
- Enhanced metadata for UI rendering
- Risk level classifications
- Dependency tracking
- Execution time estimates
- Resource impact indicators

## Future Enhancements

1. **Dynamic Templates**: Runtime template generation based on environment
2. **Template Marketplace**: Shared template repository for common scenarios
3. **Version Management**: Template versioning and upgrade paths
4. **Validation Engine**: Enhanced validation with business rule checking
5. **Integration APIs**: REST endpoints for template management
