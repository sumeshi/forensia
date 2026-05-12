<script lang="ts">
  export let checked = false;
  export let onChange: (value: boolean) => void = () => {};
</script>

<label class="toggle">
  <input type="checkbox" bind:checked on:change={() => onChange(checked)} />
  <span>suppressed を表示</span>
</label>
