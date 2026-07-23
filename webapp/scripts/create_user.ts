import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await bcrypt.hash('1234567890', 12);
  const user = await prisma.user.upsert({
    where: { email: 'nisargp631@gmail.com' },
    update: {
      password: hashedPassword,
      role: 'admin',
    },
    create: {
      email: 'nisargp631@gmail.com',
      name: 'Nisarg Dedakiya',
      password: hashedPassword,
      role: 'admin',
    },
  });
  console.log('User successfully created/updated:');
  console.log('ID:', user.id);
  console.log('Email:', user.email);
  console.log('Role:', user.role);
}

main()
  .catch((err) => {
    console.error('Error creating user:', err);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
