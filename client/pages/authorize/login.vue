<script lang="ts" setup>
async function gotoRegister() {
  const currentUri = new URL(window.location.href)
  const path = currentUri.pathname.split('/').slice(0, -1).join('/') + '/register'
  const parameters = currentUri.search
  await navigateTo(`${path}${parameters}`);
}
</script>

<template>
  <div class="flex justify-center" style="height: 100vh; align-items: center;">
    <UCard style="width: 512px; height: fit-content;">
      <template #header>
        <h1 class="text-2xl font-semibold">Login</h1>
      </template>
      <loginGroup />
      <template #footer>
        <div class="flex justify-center">
          <UButton block variant="ghost" @click="gotoRegister()" color="primary">Don't have an account? Sign Up</UButton>
        </div>
      </template>
    </UCard>
  </div>
</template>

<style scoped></style>
