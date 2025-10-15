import 'dotenv/config';
import admin from 'firebase-admin';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  teamDepartments,
  teamMembers,
  teamTasks,
  teamTaskUpdates,
  teamEvents
} from '../team-data.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const getEnv = (key, fallback) => {
  const value = process.env[key];
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
};

const loadServiceAccount = () => {
  const json = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (json && json.trim()) {
    try {
      return JSON.parse(json);
    } catch (err) {
      try {
        const decoded = Buffer.from(json.trim(), 'base64').toString('utf8');
        return JSON.parse(decoded);
      } catch {
        throw new Error(`Failed to parse FIREBASE_SERVICE_ACCOUNT JSON: ${err.message}`);
      }
    }
  }
  const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (credentialsPath && credentialsPath.trim()) {
    const absolute = resolve(process.cwd(), credentialsPath.trim());
    const contents = readFileSync(absolute, 'utf8');
    return JSON.parse(contents);
  }
  throw new Error(
    'Provide Firebase credentials via FIREBASE_SERVICE_ACCOUNT or GOOGLE_APPLICATION_CREDENTIALS'
  );
};

const bootstrapAdmin = () => {
  if (admin.apps.length) return admin.app();
  const serviceAccount = loadServiceAccount();
  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
};

const withBatch = async (firestore, writer) => {
  const batch = firestore.batch();
  await writer(batch);
  await batch.commit();
};

const SEED_COLLECTIONS = {
  departments: getEnv('FIREBASE_TEAM_DEPARTMENTS_COLLECTION', 'team_departments'),
  members: getEnv('FIREBASE_TEAM_MEMBERS_COLLECTION', 'team_members'),
  tasks: getEnv('FIREBASE_TEAM_TASKS_COLLECTION', 'team_tasks'),
  taskUpdates: getEnv('FIREBASE_TEAM_TASK_UPDATES_COLLECTION', 'team_task_updates'),
  events: getEnv('FIREBASE_TEAM_EVENTS_COLLECTION', 'team_events')
};

const seedDepartments = async (firestore) => {
  if (!teamDepartments?.length) return;
  await withBatch(firestore, (batch) => {
    teamDepartments.forEach((dept) => {
      const ref = firestore.collection(SEED_COLLECTIONS.departments).doc(dept.id);
      batch.set(ref, {
        name: dept.name || '',
        description: dept.description || '',
        lead_member_ids: dept.leadMemberIds || [],
        channels: dept.channels || {},
        created_at: admin.firestore.FieldValue.serverTimestamp()
      });
    });
  });
  console.log(`Seeded ${teamDepartments.length} departments → ${SEED_COLLECTIONS.departments}`);
};

const seedMembers = async (firestore) => {
  if (!teamMembers?.length) return;
  await withBatch(firestore, (batch) => {
    teamMembers.forEach((member) => {
      const ref = firestore.collection(SEED_COLLECTIONS.members).doc(member.id);
      batch.set(ref, {
        display_name: member.displayName || member.loginId || member.id,
        login_id: member.loginId || member.id,
        identifiers: Array.isArray(member.identifiers)
          ? member.identifiers
          : [member.loginId || member.displayName].filter(Boolean),
        access_code: member.accessCode || '',
        role: member.role || '',
        department_id: member.departmentId || '',
        email: member.email || '',
        active: member.active !== false,
        created_at: admin.firestore.FieldValue.serverTimestamp()
      });
    });
  });
  console.log(`Seeded ${teamMembers.length} members → ${SEED_COLLECTIONS.members}`);
};

const seedTasks = async (firestore) => {
  if (!teamTasks?.length) return;
  await withBatch(firestore, (batch) => {
    teamTasks.forEach((task) => {
      const ref = firestore.collection(SEED_COLLECTIONS.tasks).doc(task.id);
      batch.set(ref, {
        title: task.title || '',
        description: task.description || '',
        department_id: task.departmentId || '',
        owner_ids: task.ownerIds || [],
        status: task.status || 'todo',
        priority: task.priority || 'medium',
        due_at: task.dueAt || '',
        created_by: task.createdBy || '',
        created_at: task.createdAt || new Date().toISOString(),
        checklist: task.checklist || [],
        updates_count: task.updatesCount || 0,
        last_update_id: task.lastUpdate?.id || '',
        last_update_member_id: task.lastUpdate?.memberId || '',
        last_update_note: task.lastUpdate?.note || '',
        last_update_status: task.lastUpdate?.statusAfter || task.status || 'todo',
        last_update_at: task.lastUpdate?.createdAt || ''
      });
    });
  });
  console.log(`Seeded ${teamTasks.length} tasks → ${SEED_COLLECTIONS.tasks}`);
};

const seedTaskUpdates = async (firestore) => {
  if (!teamTaskUpdates?.length) return;
  await withBatch(firestore, (batch) => {
    teamTaskUpdates.forEach((update) => {
      const ref = firestore.collection(SEED_COLLECTIONS.taskUpdates).doc(update.id);
      batch.set(ref, {
        task_id: update.taskId || '',
        member_id: update.memberId || '',
        note: update.note || '',
        status_after: update.statusAfter || '',
        created_at: update.createdAt || new Date().toISOString()
      });
    });
  });
  console.log(
    `Seeded ${teamTaskUpdates.length} task updates → ${SEED_COLLECTIONS.taskUpdates}`
  );
};

const seedEvents = async (firestore) => {
  if (!teamEvents?.length) return;
  await withBatch(firestore, (batch) => {
    teamEvents.forEach((event) => {
      const ref = firestore.collection(SEED_COLLECTIONS.events).doc(event.id);
      batch.set(ref, {
        title: event.title || '',
        description: event.description || '',
        start_at: event.startAt || '',
        end_at: event.endAt || '',
        location: event.location || '',
        link: event.link || '',
        hosts: event.hosts || [],
        department_ids: event.departmentIds || [],
        created_at: admin.firestore.FieldValue.serverTimestamp()
      });
    });
  });
  console.log(`Seeded ${teamEvents.length} events → ${SEED_COLLECTIONS.events}`);
};

const main = async () => {
  const app = bootstrapAdmin();
  const firestore = app.firestore();

  await seedDepartments(firestore);
  await seedMembers(firestore);
  await seedTasks(firestore);
  await seedTaskUpdates(firestore);
  await seedEvents(firestore);

  console.log('Seeding complete ✅');
  process.exit(0);
};

main().catch((err) => {
  console.error('Failed to seed team data', err);
  process.exit(1);
});
