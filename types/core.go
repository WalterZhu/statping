package types

import (
	"sort"
	"time"
)

// Core struct contains all the required fields for Statup. All application settings
// will be saved into 1 row in the 'core' table. You can use the core.CoreApp
// global variable to interact with the attributes to the application, such as services.
type Core struct {
	Name           string          `gorm:"not null;column:name" json:"name"`
	Description    string          `gorm:"not null;column:description" json:"description,omitempty"`
	Config         string          `gorm:"column:config" json:"-"`
	ApiKey         string          `gorm:"column:api_key" json:"-"`
	ApiSecret      string          `gorm:"column:api_secret" json:"-"`
	Style          string          `gorm:"not null;column:style" json:"style,omitempty"`
	Footer         string          `gorm:"not null;column:footer" json:"footer,omitempty"`
	Domain         string          `gorm:"not null;column:domain" json:"domain,omitempty"`
	Version        string          `gorm:"column:version" json:"version"`
	MigrationId    int64           `gorm:"column:migration_id" json:"migration_id,omitempty"`
	UseCdn         bool            `gorm:"column:use_cdn;default:false" json:"using_cdn,omitempty"`
	CreatedAt      time.Time       `gorm:"column:created_at" json:"created_at"`
	UpdatedAt      time.Time       `gorm:"column:updated_at" json:"updated_at"`
	DbConnection   string          `gorm:"-" json:"database"`
	Started        time.Time       `gorm:"-" json:"started_on"`
	dbServices     []*Service      `gorm:"-" json:"services,omitempty"`
	Plugins        []Info          `gorm:"-" json:"-"`
	Repos          []PluginJSON    `gorm:"-" json:"-"`
	AllPlugins     []PluginActions `gorm:"-" json:"-"`
	Communications []AllNotifiers  `gorm:"-" json:"-"`
	CoreInterface  `gorm:"-" json:"-"`
}

type ServiceOrder []*Service

func (c ServiceOrder) Len() int           { return len(c) }
func (c ServiceOrder) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
func (c ServiceOrder) Less(i, j int) bool { return c[i].Order < c[j].Order }

func (c *Core) SetServices(s []*Service) {
	sort.Sort(ServiceOrder(c.dbServices))
	c.dbServices = s
}

func (c *Core) UpdateService(index int, s *Service) {
	c.dbServices[index] = s
}

func (c *Core) AddService(s *Service) {
	c.dbServices = append(c.dbServices, s)
}

func (c *Core) RemoveService(s int) []*Service {
	slice := c.dbServices
	c.dbServices = append(slice[:s], slice[s+1:]...)
	return c.dbServices
}

func (c *Core) GetServices() []*Service {
	return c.dbServices
}

type CoreInterface interface {
	SelectAllServices() ([]*Service, error)
	Services() []*Service
}