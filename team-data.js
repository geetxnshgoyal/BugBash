export const teamDepartments = [
  {
    id: 'dept-marketing',
    name: 'Marketing',
    description: 'Campaigns, countdown posts, and pre-event buzz.',
    leadMemberIds: [],
    channels: {
      whatsapp: '#',
      slack: '#marketing-team'
    }
  },
  {
    id: 'dept-logistics',
    name: 'Logistics',
    description: 'Venue layouts, vendor coordination, and member deployment.',
    leadMemberIds: ['mem-anant'],
    channels: {
      whatsapp: '#',
      slack: '#logistics'
    }
  },
  {
    id: 'dept-hospitality',
    name: 'Hospitality',
    description: 'Travel coordination, accommodation, and welcome desks.',
    leadMemberIds: ['mem-utsav'],
    channels: {
      whatsapp: '#',
      slack: '#hospitality'
    }
  },
  {
    id: 'dept-tech',
    name: 'Tech Support',
    description: 'Internal portals, AV checks, and helpdesk readiness.',
    leadMemberIds: [],
    channels: {
      whatsapp: '#',
      slack: '#tech-support'
    }
  },
  {
    id: 'dept-design',
    name: 'Design',
    description: 'Décor, printables, and swag items.',
    leadMemberIds: ['mem-sidharth'],
    channels: {
      whatsapp: '#',
      slack: '#design-team'
    }
  },
  {
    id: 'dept-sponsor',
    name: 'Sponsor',
    description: 'Partner outreach and on-site sponsor experience.',
    leadMemberIds: ['mem-atul'],
    channels: {
      whatsapp: '#',
      slack: '#sponsor-relations'
    }
  },
  {
    id: 'dept-media',
    name: 'Media Outreach',
    description: 'Press, photo/video crew, and live coverage.',
    leadMemberIds: ['mem-raaj'],
    channels: {
      whatsapp: '#',
      slack: '#media-outreach'
    }
  }
];

export const teamMembers = [
  {
    id: 'mem-anant',
    displayName: 'Anant',
    loginId: 'anant',
    email: '',
    role: 'lead',
    departmentId: 'dept-logistics',
    accessCode: 'anant@2025',
    identifiers: ['anant']
  },
  {
    id: 'mem-atul',
    displayName: 'Atul',
    loginId: 'atul',
    email: '',
    role: 'lead',
    departmentId: 'dept-sponsor',
    accessCode: 'atul2025!',
    identifiers: ['atul']
  },
  {
    id: 'mem-raaj',
    displayName: 'Raaj',
    loginId: 'raaj',
    email: '',
    role: 'lead',
    departmentId: 'dept-media',
    accessCode: 'raaj123',
    identifiers: ['raaj']
  },
  {
    id: 'mem-utsav',
    displayName: 'Utsav',
    loginId: 'utsav',
    email: '',
    role: 'lead',
    departmentId: 'dept-hospitality',
    accessCode: 'utsav2025',
    identifiers: ['utsav']
  },
  {
    id: 'mem-sidharth',
    displayName: 'Sidharth',
    loginId: 'sidharth',
    email: '',
    role: 'lead',
    departmentId: 'dept-design',
    accessCode: 'sidharth123',
    identifiers: ['sidharth']
  }
  ,
  {
    id: 'mem-aksh',
    displayName: 'Aksh',
    loginId: 'aksh',
    email: '',
    role: 'member',
    departmentId: 'dept-marketing',
    accessCode: 'aksh2025',
    identifiers: ['aksh']
  },
  {
    id: 'mem-ravi',
    displayName: 'Ravi',
    loginId: 'ravi',
    email: '',
    role: 'member',
    departmentId: 'dept-marketing',
    accessCode: 'ravi@789',
    identifiers: ['ravi']
  },
  {
    id: 'mem-saurabh',
    displayName: 'Saurabh',
    loginId: 'saurabh',
    email: '',
    role: 'member',
    departmentId: 'dept-logistics',
    accessCode: 'saurabh123!',
    identifiers: ['saurabh']
  },
  {
    id: 'mem-bibhukesh',
    displayName: 'Bibhukesh',
    loginId: 'bibhukesh',
    email: '',
    role: 'member',
    departmentId: 'dept-logistics',
    accessCode: 'bibhukesh01',
    identifiers: ['bibhukesh']
  },
  {
    id: 'mem-prateek',
    displayName: 'Prateek',
    loginId: 'prateek',
    email: '',
    role: 'member',
    departmentId: 'dept-hospitality',
    accessCode: 'prateek@2025',
    identifiers: ['prateek']
  },
  {
    id: 'mem-vani',
    displayName: 'Vani',
    loginId: 'vani',
    email: '',
    role: 'member',
    departmentId: 'dept-design',
    accessCode: 'vani123!',
    identifiers: ['vani']
  },
  {
    id: 'mem-harikrishna',
    displayName: 'Harikrishna',
    loginId: 'harikrishna',
    email: '',
    role: 'member',
    departmentId: 'dept-logistics',
    accessCode: 'hari2025!',
    identifiers: ['harikrishna', 'hari']
  },
  {
    id: 'mem-saubhagya',
    displayName: 'Saubhagya',
    loginId: 'saubhagya',
    email: '',
    role: 'member',
    departmentId: 'dept-design',
    accessCode: 'saubhagya1!',
    identifiers: ['saubhagya']
  },
  {
    id: 'mem-sahitya',
    displayName: 'Sahitya',
    loginId: 'sahitya',
    email: '',
    role: 'member',
    departmentId: 'dept-design',
    accessCode: 'sahitya@22',
    identifiers: ['sahitya']
  },
  {
    id: 'mem-abhay',
    displayName: 'Abhay',
    loginId: 'abhay',
    email: '',
    role: 'member',
    departmentId: 'dept-sponsor',
    accessCode: 'abhay@2025',
    identifiers: ['abhay']
  },
  {
    id: 'mem-sadiqua',
    displayName: 'Sadiqua',
    loginId: 'sadiqua',
    email: '',
    role: 'member',
    departmentId: '',
    accessCode: 'sadiqua@23',
    identifiers: ['sadiqua']
  },
  {
    id: 'mem-rachana',
    displayName: 'Rachana',
    loginId: 'rachana',
    email: '',
    role: 'member',
    departmentId: 'dept-hospitality',
    accessCode: 'rachana@01',
    identifiers: ['rachana']
  },
  {
    id: 'mem-angela',
    displayName: 'Angela',
    loginId: 'angela',
    email: '',
    role: 'Mentor',
    departmentId: '',
    accessCode: 'angela1@',
    identifiers: ['angela']
  },
  {
    id: 'mem-vivaan',
    displayName: 'Vivaan',
    loginId: 'vivaan',
    email: '',
    role: 'Mentor',
    departmentId: '',
    accessCode: 'vivaan@1!',
    identifiers: ['vivaan']
  },
  {
    id: 'mem-abhijit',
    displayName: 'Abhijit',
    loginId: 'abhijit',
    email: '',
    role: 'Mentor',
    departmentId: '',
    accessCode: 'abhijit10@',
    identifiers: ['abhijit']
  },
];

export const teamTasks = [
  {
    id: 'task-design-brochure',
    title: 'Create event brochure',
    description: 'Design the Bug Bash 2025 brochure covering schedule, tracks, and sponsor pages.',
    departmentId: 'dept-design',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-11-01T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Collect copy from program team', 'Include sponsor placements', 'Export print + digital versions']
  },
  {
    id: 'task-design-standee',
    title: 'Design event standee',
    description: 'Produce entrance standee artwork with keynote time and safety guidelines.',
    departmentId: 'dept-design',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-11-03T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Check venue standee dimensions', 'Highlight event hashtags', 'Share for sponsor review']
  },
  {
    id: 'task-design-poster',
    title: 'Create poster set',
    description: 'Poster series for labs, mentor lounge, and registration desk.',
    departmentId: 'dept-design',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-11-05T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Get copy from marketing', 'Prepare portrait + landscape versions']
  },
  {
    id: 'task-design-logo',
    title: 'Finalize BugBash 2025 logo lockup',
    description: 'Deliver vector + raster formats for sponsor usage and swag.',
    departmentId: 'dept-design',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-10-28T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Finalize color palette', 'Prepare monochrome version', 'Upload to brand folder']
  },
  {
    id: 'task-design-standee-tracks',
    title: 'Create track standee set',
    description: 'Individual standees for each hackathon track with QR to mentor rosters.',
    departmentId: 'dept-design',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-11-06T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Coordinate track colors with marketing', 'Add sponsor footer strip']
  },
  {
    id: 'task-sponsor-monetary',
    title: 'Secure monetary sponsor',
    description: 'Close one cash partner for prize pool top-up and venue ops.',
    departmentId: 'dept-sponsor',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-10-30T12:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Shortlist prospects', 'Share updated sponsor deck', 'Schedule pitch call']
  },
  {
    id: 'task-sponsor-food',
    title: 'Lock food sponsor',
    description: 'Get meal partner for hackathon weekend with veg/non-veg options.',
    departmentId: 'dept-sponsor',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-11-02T12:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Confirm meal schedule', 'Check dietary requirements', 'Align branding deliverables']
  },
  {
    id: 'task-logistics-printer',
    title: 'Find printing vendor',
    description: 'Identify vendor for brochures, standees, badges, and signage.',
    departmentId: 'dept-logistics',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-10-27T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Collect design specs from design team', 'Get quotes from 3 vendors', 'Share shortlist with finance']
  },
  {
    id: 'task-logistics-masterlist',
    title: 'Prepare logistics master checklist',
    description: 'Compile every item needed across tracks, hospitality, and stage.',
    departmentId: 'dept-logistics',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-10-29T10:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Gather requirements from each department', 'Mark rental vs purchase', 'Submit budget for approval']
  },
  {
    id: 'task-media-reels',
    title: 'Produce teaser reels',
    description: 'Shoot and edit two 30-sec reels for Instagram and YouTube Shorts.',
    departmentId: 'dept-media',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-11-05T14:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Gather footage from last year', 'Write script with marketing', 'Schedule publish dates']
  },
  {
    id: 'task-media-posts',
    title: 'Design social posts',
    description: 'Coordinate with design to roll out 5 countdown posts + speaker spotlight.',
    departmentId: 'dept-media',
    ownerIds: [],
    status: 'todo',
    priority: 'medium',
    dueAt: '2025-11-04T16:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Draft copy with marketing', 'Collect speaker headshots', 'Schedule posts in Buffer']
  },
  {
    id: 'task-marketing-registrations',
    title: 'Drive registrations sprint',
    description: 'Run targeted outreach to hit registration target for BugBash 2025.',
    departmentId: 'dept-marketing',
    ownerIds: [],
    status: 'todo',
    priority: 'high',
    dueAt: '2025-11-07T18:00:00.000Z',
    createdBy: '',
    createdAt: new Date().toISOString(),
    checklist: ['Launch referral post', 'Coordinate campus ambassador blast', 'Share daily signup report']
  }
];

export const teamTaskUpdates = [
  {
    id: 'update-decor-1',
    taskId: 'task-venue-decor',
    memberId: 'mem-sidharth',
    note: 'Vendor shared revised stage mock-ups; coordinating power requirements with Anant.',
    statusAfter: 'in_progress',
    createdAt: '2025-02-03T11:20:00.000Z'
  },
  {
    id: 'update-banner-1',
    taskId: 'task-banner-print',
    memberId: 'mem-anant',
    note: 'Collected sponsor artwork; waiting on final media outreach tagline before sending to print.',
    statusAfter: 'todo',
    createdAt: '2025-02-04T09:05:00.000Z'
  },
  {
    id: 'update-press-1',
    taskId: 'task-press-brief',
    memberId: 'mem-raaj',
    note: 'Drafted press outline and pulled stats from last year; need Atul to confirm sponsor highlights.',
    statusAfter: 'todo',
    createdAt: '2025-02-03T15:45:00.000Z'
  },

];

export const teamEvents = [];
